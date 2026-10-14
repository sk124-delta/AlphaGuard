"""Scheduled ValueSERP scans for active AlphaGuard protected assets."""

import logging
from datetime import datetime, timezone
from typing import Any

from apscheduler.schedulers.blocking import BlockingScheduler

from .db import (
    DatabaseError,
    get_active_protected_assets,
    get_detected_match_links,
    get_user_profile,
    get_user_tier,
    get_user_match_count,
    prepare_due_takedown_escalations,
    save_detected_match,
    save_takedown_notice,
    update_user_match_count,
)
from .scanner import ScannerError, scan_image_valueserp
from .url_utils import filter_whitelisted_matches


LOGGER = logging.getLogger(__name__)
SCAN_INTERVAL_HOURS = 24


def run_scan_cycle() -> int:
    """Scan every active asset once and return the number of new matches saved."""
    new_matches_by_user: dict[str, int] = {}

    assets = get_active_protected_assets()

    def has_priority(asset: dict[str, Any]) -> bool:
        try:
            return get_user_tier(str(asset["user_id"])) == "Enterprise"
        except DatabaseError:
            LOGGER.exception("Could not determine scan priority for asset %s", asset.get("id"))
            return False

    assets.sort(key=has_priority, reverse=True)
    try:
        escalated_count = prepare_due_takedown_escalations()
        if escalated_count:
            LOGGER.info("Prepared drafts for %s overdue takedown notice(s)", escalated_count)
    except DatabaseError:
        LOGGER.exception("Could not prepare overdue takedown escalation drafts")

    for asset in assets:
        asset_id = int(asset["id"])
        user_id = str(asset["user_id"])
        image_url = str(asset.get("image_url") or "").strip()
        if not image_url:
            continue

        try:
            tier = get_user_tier(user_id)
            profile = get_user_profile(user_id)
            trial_end = (profile or {}).get("trial_end_date")
            trial_active = False
            if trial_end:
                trial_end_date = datetime.fromisoformat(
                    str(trial_end).replace("Z", "+00:00")
                )
                if trial_end_date.tzinfo is None:
                    trial_end_date = trial_end_date.replace(tzinfo=timezone.utc)
                trial_active = datetime.now(timezone.utc) <= trial_end_date
            if tier not in {"Standard", "Enterprise", "Pro", "Pro (Full Auto)"} and not trial_active:
                continue
            results = filter_whitelisted_matches(
                scan_image_valueserp(image_url),
                str((profile or {}).get("whitelisted_partners") or ""),
            )
            existing_links = get_detected_match_links(asset_id, (result.link for result in results))
            seen_links = set(existing_links)
            new_results = []
            for result in results:
                if result.link and result.link not in seen_links:
                    seen_links.add(result.link)
                    new_results.append(result)
            for result in new_results:
                save_detected_match(user_id, asset_id, image_url, result)
                if profile and profile.get("id"):
                    save_takedown_notice(
                        str(profile["id"]), result.link, result.thumbnail or ""
                    )
            if new_results:
                new_matches_by_user[user_id] = new_matches_by_user.get(user_id, 0) + len(new_results)
        except (ScannerError, DatabaseError):
            LOGGER.exception("Scheduled scan failed for protected asset %s", asset_id)

    total_new_matches = 0
    for user_id, new_count in new_matches_by_user.items():
        try:
            update_user_match_count(user_id, get_user_match_count(user_id) + new_count)
            total_new_matches += new_count
        except DatabaseError:
            LOGGER.exception("Could not update match count for user %s", user_id)

    return total_new_matches


def create_scheduler() -> BlockingScheduler:
    """Create the 24-hour scheduler without starting it."""
    scheduler = BlockingScheduler(timezone="UTC")
    scheduler.add_job(
        run_scan_cycle,
        trigger="interval",
        hours=SCAN_INTERVAL_HOURS,
        id="alphaguard-value-serp-scan",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    return scheduler


def main() -> None:
    """Run an initial scan, then continue scanning every 24 hours."""
    logging.basicConfig(level=logging.INFO)
    run_scan_cycle()
    scheduler = create_scheduler()
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()


if __name__ == "__main__":
    main()