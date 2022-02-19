# gunicorn.conf.py
# Non logging stuff
# bind = "0.0.0.0:80"
# workers = 3
# Access log - records incoming HTTP requests
accesslog = "/home/bilen/programs/django/logs/gunicorn.access.log"
# Error log - records Gunicorn server goings-on
errorlog = "/home/bilen/programs/django/logs/gunicorn.error.log"
# Whether to send Django output to the error log 
capture_output = True
# How verbose the Gunicorn error logs should be 
loglevel = "info"
