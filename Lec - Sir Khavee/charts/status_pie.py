from bokeh.plotting import figure
from bokeh.palettes import Category10
from bokeh.models import ColumnDataSource
from bokeh.transform import cumsum
from math import pi


def status_pie(df):
    status_counts = df['status'].value_counts()
    data = status_counts.reset_index(name='value').rename(columns={'index': 'status'})
    data['angle'] = data['value'] / data['value'].sum() * 2 * pi
    data['color'] = Category10[10][:len(data)]
    source = ColumnDataSource(data)

    fig = figure(height=300, title="User Status (Active vs Inactive)", toolbar_location=None,
                 tools="hover", tooltips="@status: @value", x_range=(-0.5, 1.0))
    fig.wedge(x=0, y=1, radius=0.4,
              start_angle=cumsum('angle', include_zero=True), end_angle=cumsum('angle'),
              line_color="white", fill_color='color', legend_field='status', source=source)
    fig.axis.visible = False
    fig.grid.grid_line_color = None
    return fig