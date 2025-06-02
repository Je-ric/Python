from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool
from bokeh.transform import factor_cmap
from bokeh.palettes import Category10

def gender_distribution(df):
    gender_counts = df['gender'].value_counts()
    genders = gender_counts.index.tolist()
    source = ColumnDataSource(data=dict(gender=genders, count=gender_counts.values))

    # Use a palette with as many colors as unique genders
    palette = Category10[max(3, len(genders))]  # At least 3 colors

    fig = figure(x_range=genders, height=450, width=700, title="Gender Distribution",
                 toolbar_location="above", tools="pan,wheel_zoom,box_zoom,reset")

    # Color bars differently using factor_cmap
    bars = fig.vbar(x='gender', top='count', width=0.8, source=source,
                    fill_color=factor_cmap('gender', palette=palette, factors=genders),
                    line_color="black", hover_fill_color="orange")

    # Add hover tool
    hover = HoverTool(tooltips=[("Gender", "@gender"), ("Count", "@count")], renderers=[bars])
    fig.add_tools(hover)

    fig.xgrid.grid_line_color = None
    fig.y_range.start = 0

    return fig
