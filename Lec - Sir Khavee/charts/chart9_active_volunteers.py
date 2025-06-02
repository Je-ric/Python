from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool
import numpy as np

def chart(df):
    # Filter active volunteers
    active_volunteers = df[(df['status'] == 'active') & (df['isVolunteer'] == True)]
    
    # Group by program and get counts
    counts = active_volunteers['programName'].value_counts().sort_values(ascending=False)
    programs = counts.index.tolist()
    
    # Prepare data: each volunteer is one dot, so repeat programs by count
    program_list = []
    for prog, cnt in counts.items():
        program_list.extend([prog] * cnt)
        
    # Assign y positions as categories (program names)
    y_positions = program_list
    
    # Jitter x positions (random scatter horizontally)
    np.random.seed(42)  # For reproducibility
    x_jitter = np.random.uniform(-0.4, 0.4, len(program_list))
    
    # Assign colors to each program
    palette = ['#e41a1c', '#377eb8', '#4daf4a', '#984ea3', '#ff7f00',
               '#ffff33', '#a65628', '#f781bf', '#999999']  # Colorblind-safe palette
    color_map = {prog: palette[i % len(palette)] for i, prog in enumerate(programs)}
    colors = [color_map[prog] for prog in program_list]
    
    source = ColumnDataSource(data=dict(
        x=x_jitter,
        y=y_positions,
        program=y_positions,
        color=colors,
    ))
    
    p = figure(y_range=programs, height=400, width=700,
               title="Active Volunteers by Program (Jittered Dot Plot)",
               x_range=(-1, 1),
               toolbar_location="above", tools="pan,box_zoom,reset,save")
    
    # Plot jittered circles
    p.circle('x', 'y', size=10, color='color', alpha=0.7, line_color='black', source=source)
    
    # Hide x-axis (no meaningful value)
    p.xaxis.visible = False
    
    # Add hover tool
    hover = HoverTool(tooltips=[
        ("Program", "@program"),
    ])
    p.add_tools(hover)
    
    # Clean grid & labels
    p.ygrid.grid_line_color = None
    p.xgrid.grid_line_color = None
    p.yaxis.axis_label = "Program"
    
    return p
