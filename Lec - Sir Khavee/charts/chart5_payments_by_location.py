from bokeh.plotting import figure
from bokeh.models import ColumnDataSource

def chart(df):
    membership_payments = df.groupby('location')['membershipPayment'].sum().sort_values(ascending=False)
    membership_source = ColumnDataSource(data=dict(location=membership_payments.index.tolist(), totalPayment=membership_payments.values))

    p = figure(x_range=membership_payments.index.tolist(), height=300, title="Total Membership Payments by Location",
               toolbar_location=None, tools="")
    p.vbar(x='location', top='totalPayment', width=0.9, source=membership_source)
    p.xaxis.major_label_orientation = 3.14 / 4
    p.y_range.start = 0
    return p
