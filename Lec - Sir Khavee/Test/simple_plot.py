from bokeh.plotting import figure, output_file, show

output_file("plot.html")  # This will create 'plot.html' in your current folder

p = figure(title="Simple Line Plot", x_axis_label='x', y_axis_label='y')

p.line([1, 2, 3, 4, 5], [6, 7, 2, 4, 5], line_width=2)

show(p)
