# AuthorisedDataFrame

Row-level security for pandas DataFrames.

::: cognito_auth.df.AuthorisedDataFrame
    options:
      show_root_heading: true
      show_source: true
      members:
        - __init__
        - from_dataframe
        - to_store

## Installation

AuthorisedDataFrame requires the `[df]` extra:

```bash
pip install cognito-auth[df]

# Or with Dash support:
pip install cognito-auth[dash,df]
```

## Quick Start

```python
from cognito_auth.dash import DashAuth
from cognito_auth.df import AuthorisedDataFrame

auth = DashAuth()
auth.protect_app(app)

# Pre-segment your data once at startup
df = pd.read_csv("data/spending.csv")
SEGMENTS = dict(tuple(df.groupby("department")))

DOMAIN_MAPPING = {
    "cabinetoffice.gov.uk": ["Cabinet Office"],
    "homeoffice.gov.uk": ["Home Office"],
    "hmrc.gov.uk": ["HMRC"],
}
```

## Simple: Single DataFrame

The most straightforward usage -- one DataFrame, one callback, filtered by user:

```python
@app.callback(
    Output("filtered-data", "data"),
    Input("trigger", "n_intervals"),
)
def filter_and_store(_n):
    user = auth.get_auth_user()
    secure = AuthorisedDataFrame(SEGMENTS, user, DOMAIN_MAPPING)

    if not secure.has_access:
        return None

    return secure.to_store()
```

`to_store()` returns a dict with `records`, `user_name`, `user_email`, `departments`, and `has_access` -- ready to write to `dcc.Store`. Downstream callbacks read from the Store:

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

## DataModel: Multiple DataFrames

For apps with multiple data sources, create one `AuthorisedDataFrame` per source:

```python
class DashboardDataModel:
    def __init__(self, spending_df, forecast_df, domain_mapping):
        self._spending_segments = dict(tuple(spending_df.groupby("department")))
        self._forecast_segments = dict(tuple(forecast_df.groupby("department")))
        self._mapping = domain_mapping

    def secure_spending(self, user):
        return AuthorisedDataFrame(
            self._spending_segments, user, self._mapping
        )

    def secure_forecasts(self, user):
        return AuthorisedDataFrame(
            self._forecast_segments, user, self._mapping
        )
```

```python
@app.callback(...)
def filter_and_store(_n):
    user = auth.get_auth_user()
    spending = data_model.secure_spending(user)
    forecasts = data_model.secure_forecasts(user)

    if not spending.has_access:
        return None

    return {
        "spending": spending.df.to_dict("records"),
        "forecasts": forecasts.df.to_dict("records"),
    }
```

## Convenience: from_dataframe()

If you don't want to pre-segment, use `from_dataframe()` which segments on the fly:

```python
secure = AuthorisedDataFrame.from_dataframe(
    df, "department", user, DOMAIN_MAPPING
)
```

!!! tip "Pre-segment for performance"
    For apps with repeated calls (e.g. multiple callbacks), pre-segment once at startup and use the main constructor. `from_dataframe()` re-segments on every call.

## How It Works

1. **User resolution**: The user's `email_domain` is looked up in the `domain_mapping` dict. Admin users (`user.is_admin`) get access to all departments.
2. **Segment lookup**: The matching department DataFrames are retrieved via dict lookup -- O(1) per department, no full DataFrame scan.
3. **Filtered `.df`**: The resulting `.df` property contains only the authorised rows. There is no way to access unfiltered data through the wrapper.

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
