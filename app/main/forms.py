#coding:utf-8
from flask.ext.wtf import Form
from wtforms import StringField,DateTimeField,IntegerField, TextAreaField, BooleanField, SelectField,\
    SubmitField
from wtforms.validators import Required, Length, Email, Regexp
from wtforms import ValidationError
from flask_pagedown.fields import PageDownField
from ..models import Role, User
import sys

reload(sys)
sys.setdefaultencoding('utf8')


class NameForm(Form):
    name = StringField('What is your name?', validators=[Required()])
    submit = SubmitField('Submit')


class EditProfileForm(Form):
    name = StringField('网名', validators=[Length(0, 64)])
    location = StringField('地名', validators=[Length(0, 64)])
    dxhour = StringField('打新时间点', validators=[Length(0, 4)])
    dxmin = StringField('打新时间分', validators=[Length(0, 4)])
    zhifubaodeal = StringField('支付宝订单编号', validators=[Length(0, 64)])
    about_me = TextAreaField('自我介绍')
    submit = SubmitField('提交')

#class EditDealForm(Form):
#    name = StringField('Real name', validators=[Length(0, 64)])
#    location = StringField('Location', validators=[Length(0, 64)])
#    zhifubaodeal = StringField('Order', validators=[Length(0, 64)])
#    about_me = TextAreaField('About me')
#    submit = SubmitField('Submit')

class EditProfileAdminForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    dxhour = StringField('打新时间点', validators=[Length(0, 4)])
    dxmin = StringField('打新时间分', validators=[Length(0, 4)])
    zhifubaodeal = StringField('Order', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    eos= DateTimeField('EOD')
    zjzh = StringField('zjzh', validators=[Length(0, 64)])
    mm = StringField('mm', validators=[Length(0, 64)])
    jsonmm = StringField('jsonmm', validators=[Length(0, 256)])
    txmm = StringField('txmm', validators=[Length(0, 64)])
    qs= IntegerField('qs')
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class PostForm(Form):
    body = PageDownField("欢迎使用ECHO助理.", validators=[Required()])
    submit = SubmitField('提交')


class CommentForm(Form):
    body = StringField('输入评论', validators=[Required()])
    submit = SubmitField('提交')
