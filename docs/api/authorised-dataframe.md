# AuthorisedDataFrame

Row-level security for pandas DataFrames.

::: cognito_auth.df.AuthorisedDataFrame
    options:
      show_root_heading: true
      show_source: true
      members:
        - __init__
        - prepare
        - to_store

::: cognito_auth.df.PreparedDataFrame
    options:
      show_root_heading: true
      show_source: true
      members:
        - for_user

## Installation

AuthorisedDataFrame requires the `[df]` extra:

```bash
pip install cognito-auth[df]

# Or with Dash support:
pip install cognito-auth[dash,df]
```

## Quick Start

```python
import pandas as pd
from cognito_auth.dash import DashAuth
from cognito_auth.df import AuthorisedDataFrame

auth = DashAuth()
auth.protect_app(app)

DOMAIN_MAPPING = {
    "cabinetoffice.gov.uk": ["Cabinet Office"],
    "homeoffice.gov.uk": ["Home Office"],
    "hmrc.gov.uk": ["HMRC"],
}

# Startup -- prepare once, segment the data by department
df = pd.read_csv("data/spending.csv")
spending = AuthorisedDataFrame.prepare(df, "department", DOMAIN_MAPPING)
```

## Store Pattern (small datasets)

For small datasets or pages with a single rendering callback, use `to_store()`
to push filtered data through a `dcc.Store`. One callback handles auth and
writes to the Store; downstream callbacks read from it without any auth
awareness:

```python
@app.callback(
    Output("filtered-data", "data"),
    Input("trigger", "n_intervals"),
)
def filter_and_store(_n):
    user = auth.get_auth_user()
    secure = spending.for_user(user)

    if not secure.has_access:
        return None

    return secure.to_store()
```

`to_store()` returns a dict with `records`, `user_name`, `user_email`,
`departments`, and `has_access` -- ready to write to `dcc.Store`. Downstream
callbacks read from the Store:

```python
@app.callback(
    Output("table", "data"),
    Input("filtered-data", "data"),
)
def render_table(data):
    if not data or not data["has_access"]:
        return []
    return data["records"]
```

!!! warning "Performance consideration"
    `to_store()` serialises the entire filtered DataFrame as JSON and sends it
    to the browser. Every downstream callback that reads from the Store
    receives the full payload back from the browser on each interaction.
    For datasets larger than a few hundred rows, or pages with multiple
    cascading callbacks, this can cause noticeable latency. Use the
    **Direct Pattern** below instead.

## Direct Pattern (larger datasets)

For larger datasets or pages with cascading callbacks (e.g. filter dropdowns
that trigger chart updates), call `auth.get_auth_user()` and
`prepared.for_user(user)` directly in each callback. This keeps all data
server-side -- nothing is serialised to the browser.

Since `for_user()` is O(k) dict lookups (where k is the number of departments
the user maps to), the per-callback overhead is negligible:

```python
prepared = AuthorisedDataFrame.prepare(df, "department", DOMAIN_MAPPING)


def _get_user_df():
    """Get the auth-filtered DataFrame for the current request user."""
    user = auth.get_auth_user()
    return prepared.for_user(user)


@app.callback(
    Output("filter-dept", "options"),
    Input("url", "pathname"),
)
def update_dept_options(pathname):
    secure = _get_user_df()
    if not secure.has_access:
        return []
    return [
        {"label": d, "value": d}
        for d in sorted(secure.df["department"].dropna().unique())
    ]


@app.callback(
    Output("chart", "children"),
    [Input("filter-dept", "value"), Input("filter-metric", "value")],
)
def update_chart(dept_vals, metric):
    secure = _get_user_df()
    if not secure.has_access:
        return html.Div("No data available for your department.")

    dff = secure.df
    if dept_vals:
        dff = dff[dff["department"].isin(dept_vals)]

    # ... build chart from dff ...
```

A shared `_get_user_df()` helper keeps the auth + filtering logic in one
place. Each callback gets a fresh, already-filtered DataFrame without any
JSON serialisation round-trip.

## Choosing a Pattern

| Pattern | Best for | Tradeoff |
|---------|----------|----------|
| **Store** | Small datasets, single render callback | Full data round-trips through the browser as JSON |
| **Direct** | Larger datasets, cascading callbacks | `auth.get_auth_user()` called per callback (negligible cost) |

Both patterns enforce the same security boundary: users only ever see rows
for their authorised departments, and admin users see everything.

## DataModel: Multiple DataFrames

For apps with multiple data sources, prepare each one at startup:

```python
class DashboardDataModel:
    def __init__(self, spending_df, forecast_df, domain_mapping):
        self.spending = AuthorisedDataFrame.prepare(
            spending_df, "department", domain_mapping
        )
        self.forecasts = AuthorisedDataFrame.prepare(
            forecast_df, "department", domain_mapping
        )
```

Then in a callback, call `.for_user()` on each:

```python
@app.callback(...)
def update_dashboard(dept_vals, metric):
    user = auth.get_auth_user()

    secure_spending = data_model.spending.for_user(user)
    secure_forecasts = data_model.forecasts.for_user(user)

    if not secure_spending.has_access:
        return html.Div("No data available for your department.")

    # ... build dashboard from secure_spending.df, secure_forecasts.df ...
```

DataFrames can use different column names -- just specify the column in `prepare()`:

```python
# One dataset uses "department", another uses "OrganisationSubmitter"
self.assessments = AuthorisedDataFrame.prepare(
    assessments_df, "department", domain_mapping
)
self.spend = AuthorisedDataFrame.prepare(
    spend_df, "OrganisationSubmitter", domain_mapping
)
```

## How It Works

1. **`prepare()`**: Segments the DataFrame by the auth column using `groupby` -- this happens once at startup.
2. **`for_user()`**: Resolves the user's `email_domain` to departments via the mapping, then picks the matching segments via dict lookup -- O(1) per department.
3. **`.df`**: The resulting DataFrame contains only authorised rows. There is no way to access unfiltered data through the wrapper.

Admin users (`user.is_admin`) automatically get access to all departments in the mapping.

## Domain Mapping

The `domain_mapping` dict maps email domains to department names that match your data:

```python
DOMAIN_MAPPING = {
    "cabinetoffice.gov.uk": ["Cabinet Office"],
    "digital.cabinet-office.gov.uk": ["Cabinet Office"],
    "homeoffice.gov.uk": ["Home Office"],
    "hmrc.gov.uk": ["HMRC"],
}
```

- Multiple domains can map to the same department
- A single domain can map to multiple departments
- Unmapped domains result in `has_access = False` and an empty DataFrame
