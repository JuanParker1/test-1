from misp_app import app
from flask_apscheduler import APScheduler
from misp_app.fonctions import QRadarCheck,IOCcount
scheduler = APScheduler()


if __name__ == '__main__':
  scheduler.add_job(id ='check clients', func = QRadarCheck, trigger= 'interval', seconds= 300)
  scheduler.add_job(id ='att account', func = IOCcount, trigger= 'interval', seconds= 60)
  scheduler.start()
  app.run (debug=True)

