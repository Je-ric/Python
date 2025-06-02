from bokeh.plotting import figure
from bokeh.transform import factor_cmap
import pandas as pd

def chart(df):
    df['donation'] = pd.to_numeric(df['donation'], errors='coerce').fillna(0)
    df['membershipPayment'] = pd.to_numeric(df['membershipPayment'], errors='coerce').fillna(0)
    df['volunteerStatusStr'] = df['isVolunteer'].astype(str)

    p = figure(height=300, width=400, title="Donation vs Membership Payment",
               x_axis_label="Membership Payment (pesos)", y_axis_label="Donation (pesos)",
               tools="pan,wheel_zoom,box_zoom,reset")

    p.circle('membershipPayment', 'donation', size=7,
             color=factor_cmap('volunteerStatusStr', palette=['red', 'green'], factors=['False', 'True']),
             legend_field='volunteerStatusStr', source=df)

    p.legend.title = 'Is Volunteer'
    p.legend.location = 'top_left'
    return p
