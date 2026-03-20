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

## Simple: Single DataFrame

One DataFrame, one callback, filtered by user:

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
def filter_and_store(_n):
    user = auth.get_auth_user()

    secure_spending = data_model.spending.for_user(user)
    secure_forecasts = data_model.forecasts.for_user(user)

    if not secure_spending.has_access:
        return None

    return {
        "spending": secure_spending.df.to_dict("records"),
        "forecasts": secure_forecasts.df.to_dict("records"),
    }
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
