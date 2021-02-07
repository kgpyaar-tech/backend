from mongoengine import Document, fields


class User(Document):
    """
    MongoDB Model for the user who registers
    """
    name = fields.StringField()
    email = fields.EmailField()
    is_registered = fields.BooleanField(default=False)
    roll = fields.EmailField()
    # Store the password hash :)
    password = fields.StringField()
    nickname = fields.StringField()
    encrypted_private_key = fields.StringField()
    public_key = fields.StringField()
    # Unique hash for registration
    verify_hash = fields.StringField()
    contact_details = fields.StringField()
    year = fields.StringField()
    department = fields.StringField()
    sent_hearts = fields.ListField(fields.StringField(), default=[])
    received_hearts = fields.ListField(fields.StringField(), default=[])
    request_time_window = fields.ListField(fields.StringField(), default=[])

