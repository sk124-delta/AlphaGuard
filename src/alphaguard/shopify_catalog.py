"""Read-only Shopify Admin GraphQL catalog image discovery."""

import re
from urllib.parse import urlparse

import requests


SHOPIFY_API_VERSION = "2026-07"
MAX_CATALOG_IMAGES = 5_000
REQUEST_TIMEOUT = (5, 30)
_SHOP_DOMAIN_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.myshopify\.com$"
)
_PRODUCTS_QUERY = """
query CatalogImages($after: String) {
  products(first: 25, after: $after) {
    edges {
      node {
        id
        title
        images(first: 250) {
          edges {
            node {
              url
              altText
              width
              height
            }
          }
          pageInfo {
            hasNextPage
          }
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""


class ShopifyCatalogError(RuntimeError):
    """Raised when Shopify catalog discovery cannot complete safely."""


def normalize_shopify_domain(store_domain: str) -> str:
    """Accept only a bare Shopify-hosted store domain."""
    domain = store_domain.strip().lower().rstrip(".")
    if not _SHOP_DOMAIN_PATTERN.fullmatch(domain):
        raise ValueError("Enter a Shopify store domain ending in .myshopify.com.")
    return domain


def _shopify_graphql(
    store_domain: str,
    access_token: str,
    query: str,
    variables: dict[str, object],
) -> dict:
    endpoint = (
        f"https://{store_domain}/admin/api/{SHOPIFY_API_VERSION}/graphql.json"
    )
    try:
        response = requests.post(
            endpoint,
            headers={
                "Content-Type": "application/json",
                "X-Shopify-Access-Token": access_token,
            },
            json={"query": query, "variables": variables},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.Timeout as exc:
        raise ShopifyCatalogError("Shopify did not respond before the request timed out.") from exc
    except requests.RequestException as exc:
        raise ShopifyCatalogError("Could not connect to the Shopify store.") from exc

    if response.status_code in {401, 403}:
        raise ShopifyCatalogError(
            "Shopify rejected the token. Check that it is valid and has read_products access."
        )
    if response.status_code == 429:
        raise ShopifyCatalogError("Shopify rate-limited this sync. Try again later.")
    if response.status_code >= 400:
        raise ShopifyCatalogError(
            f"Shopify returned an HTTP {response.status_code} response."
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise ShopifyCatalogError("Shopify returned an invalid response.") from exc
    if not isinstance(payload, dict):
        raise ShopifyCatalogError("Shopify returned an invalid response.")
    if payload.get("errors"):
        raise ShopifyCatalogError(
            "Shopify could not read the catalog. Check the token's read_products scope."
        )
    return payload


def fetch_shopify_catalog_images(
    store_domain: str, access_token: str
) -> list[dict[str, object]]:
    """Fetch product image metadata without downloading images or changing products."""
    domain = normalize_shopify_domain(store_domain)
    token = access_token.strip()
    if not token or len(token) > 5_000:
        raise ValueError("Enter a valid Shopify Admin API access token.")

    assets: list[dict[str, object]] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()

    while True:
        payload = _shopify_graphql(
            domain,
            token,
            _PRODUCTS_QUERY,
            {"after": cursor},
        )
        try:
            products = payload["data"]["products"]
            edges = products["edges"]
            page_info = products["pageInfo"]
        except (KeyError, TypeError) as exc:
            raise ShopifyCatalogError("Shopify returned an incomplete product catalog.") from exc

        for product_edge in edges:
            try:
                product = product_edge["node"]
                images = product["images"]
                image_edges = images["edges"]
            except (KeyError, TypeError) as exc:
                raise ShopifyCatalogError("Shopify returned invalid product image data.") from exc
            if images.get("pageInfo", {}).get("hasNextPage"):
                raise ShopifyCatalogError(
                    "A product has more images than the sync limit supports. "
                    "No catalog assets were saved."
                )
            for image_edge in image_edges:
                try:
                    image = image_edge["node"]
                    image_url = str(image["url"]).strip()
                    parsed_url = urlparse(image_url)
                    if parsed_url.scheme != "https" or parsed_url.hostname != "cdn.shopify.com":
                        raise ShopifyCatalogError(
                            "Shopify returned a product image outside its trusted CDN."
                        )
                    assets.append(
                        {
                            "product_id": str(product["id"]),
                            "product_title": str(product.get("title") or ""),
                            "image_url": image_url,
                            "alt_text": str(image.get("altText") or ""),
                            "width": int(image.get("width") or 0),
                            "height": int(image.get("height") or 0),
                        }
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise ShopifyCatalogError(
                        "Shopify returned invalid product image metadata."
                    ) from exc
                if len(assets) > MAX_CATALOG_IMAGES:
                    raise ShopifyCatalogError(
                        f"The catalog exceeds the {MAX_CATALOG_IMAGES:,}-image sync limit. "
                        "No catalog assets were saved."
                    )

        if not page_info.get("hasNextPage"):
            break
        next_cursor = page_info.get("endCursor")
        if not next_cursor or next_cursor in seen_cursors:
            raise ShopifyCatalogError("Shopify returned an invalid pagination cursor.")
        seen_cursors.add(next_cursor)
        cursor = str(next_cursor)

    return assets
