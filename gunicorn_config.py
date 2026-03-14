import multiprocessing

bind = "127.0.0.1:5000"
workers = 1
worker_class = "gevent"
worker_connections = 100
timeout = 120
keepalive = 5
errorlog = "/opt/steamboost/logs/error.log"
accesslog = "/opt/steamboost/logs/access.log"
loglevel = "info"
