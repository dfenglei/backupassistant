#coding:utf-8
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SelectField,SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User
import sys

reload(sys)
sys.setdefaultencoding('utf8')


class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('密码', validators=[Required()])
    remember_me = BooleanField('保持登录')
    submit = SubmitField('登录')


class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                           Email()])
    username = StringField('用户名', validators=[
        Required(), Length(1, 64), Regexp('[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('密码', validators=[
        Required(), EqualTo('password2', message='密码不一致')])
    password2 = PasswordField('确认密码', validators=[Required()])
    #accountname = StringField('Username', validators=[
    #accounttype = SelectField('券商类型',validators=[Required()] , choices=[('0', '佣金宝'),('1', '华泰'),('2', '广发'),('3', '银河')] )
    accounttype = SelectField('券商类型',validators=[Required()] , choices=[('0', '银河'),('1', '广发'),('2', '中信建投'),('3', '湘财'),('4', '佣金宝')] )
    accountname = StringField('资金账户', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z0-9]*$', 0,
                                          'Accountnames must have only letters, '
                                          'numbers')])
    accountpassword = PasswordField('交易密码', validators=[
        Required(), EqualTo('accountpassword2', message='交易密码不一致')])
    accountpassword2 = PasswordField('确认交易密码', validators=[Required()])
    #txpassword = PasswordField('华泰通讯密码', validators=[
    #     EqualTo('txpassword2', message='通讯密码不一致')])
    #txpassword2 = PasswordField('确认通讯密码' )
    zhifubao = StringField('支付宝交易号', validators=[
        Required(), Length(1, 64), Regexp('^201[0-9]*$', 0,
                                          '确认你支付宝交易号是否正确 ' 'numbers')])
    submit = SubmitField('注册')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email已经被注册.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('用户名已经使用.')


class ChangePasswordForm(Form):
    old_password = PasswordField('旧密码', validators=[Required()])
    password = PasswordField('新密码', validators=[
        Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('确认新密码', validators=[Required()])
    submit = SubmitField('更新密码')


class PasswordResetRequestForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    submit = SubmitField('重置密码')


class PasswordResetForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('新密码', validators=[
        Required(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('确认新密码', validators=[Required()])
    submit = SubmitField('重置密码')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError('邮箱不对.')


class ChangeEmailForm(Form):
    email = StringField('New Email', validators=[Required(), Length(1, 64),
                                                 Email()])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Update Email Address')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
