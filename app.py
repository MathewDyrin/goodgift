from src import create_app
from src.extensions import db
from libs.serving import set_localization


app = create_app()


@app.before_first_request
def create_all():
    db.create_all()


set_localization('ru-ru')

if __name__ == '__main__':
    app.run()
