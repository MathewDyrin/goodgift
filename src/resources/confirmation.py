from flask import make_response, render_template
from flask_restful import Resource

from src.models.confirmation import ConfirmationModel
from libs.serving import response_quote


class Confirmation(Resource):
    @classmethod
    def get(cls, confirmation_id: str):
        confirmation = ConfirmationModel.find_by_id(confirmation_id)
        if not confirmation:
            return make_response(
                render_template("confirmation.html",
                                server_response=response_quote("confirmation_not_found"),
                                img_file="error.png"
                                ),
                404
            )
        if confirmation.expired:
            return make_response(
                render_template("confirmation.html",
                                server_response=response_quote("confirmation_link_expired"),
                                img_file="error.png"
                                ),
                400
            )
        if confirmation.confirmed:
            return make_response(
                render_template("confirmation.html",
                                server_response=response_quote("confirmation_link_already_confirmed"),
                                img_file="error.png"
                                ),
                400
            )

        confirmation.confirmed = True
        confirmation.save_to_db()

        headers = {"Content_Type": "text/html"}
        return make_response(
            render_template('confirmation.html',
                            server_response=response_quote("confirmation_link_confirmed"),
                            img_file="done.png"
                            ),
            200,
            headers
        )
