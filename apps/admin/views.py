from flask import Blueprint, render_template, request, session, redirect, url_for,jsonify
from .models import Users
from .forms import LoginForm
from flask import make_response
from utils.captcha import create_validate_code
from datetime import timedelta
import config
from exts import db

bp = Blueprint("admin", __name__, url_prefix='/admin')


@bp.route("/login/", methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'GET':
        return render_template('admin/login.html')
    else:
        form = LoginForm(request.form)
        if form.validate():
            user = request.form.get('username')
            pwd = request.form.get('password')
            online = request.form.get('online')
            captcha = request.form.get('captcha')
            if session.get('image').lower() != captcha.lower():
                return render_template('admin/login.html', message="验证码不对")

            users = Users.query.filter_by(username=user).first()
            if Users:
                if user == users.username and users.check_password(pwd):
                    session['user_id'] = users.uid
                    print("密码正确")
                    if online:  # 如果选择了记住我
                        session.permanent = True
                        bp.permanent_session_lifetime = timedelta(days=10)

                    return redirect(url_for('admin.index'))
                    # return "登录成功！"
                else:
                    error = "用户名或密码错误"
                    return render_template('admin/login.html', message=error)
            else:
                return render_template('admin/login.html', message="没有此用户")
        else:
            return render_template('admin/login.html', message="form.errors")


@bp.route('/')
def index():
    return render_template('admin/login.html')


# 调用验证码
@bp.route('/code/')
def get_code():
    # 把strs发给前端,或者在后台使用session保存
    code_img, strs = create_validate_code()
    buf = BytesIO()
    code_img.save(buf, 'JPEG', quality=70)
    buf_str = buf.getvalue()
    # buf.seek(0)
    response = make_response(buf_str)
    response.headers['Content-Type'] = 'image/jpeg'
    # 将验证码字符串储存在session中
    session['image'] = strs

    return response


# @bp.route('/logout/')
# @login_required
# def logout():
#    del session[user_id]
#   return redorect(url_for('admin.login'))


# 个人信息页视图
@bp.route('/profile/')
# @login_required
def profile():
    if config.ADMIN_USER_ID in session:
        user_id = session.get(config.ADMIN_USER_ID)
        user = Users.query.get(user_id)
        return render_template('admin/profile.html', user=user)


#核实校验密码
@bp.route('/checkpwd/')
#@login_required
def checkpwd():
    # user1 = request.args.get('username')
    oldpwd = request.args.get('oldpwd', '')
    # print(oldpwd)
    if config.ADMIN_USER_ID  in session:
        user_id = session.get(config.ADMIN_USER_ID)
        #user = Users.query.filter_by(username='admin').first()#这里作了修改
        user = Users.query.filter(Users.uid==user_id).first()  # 这里作了修改
        if user.check_password(oldpwd):
            data = {
                "name": user.email,
                "status": 11
            }
        else:
            data = {
                "name": None,
                "status": 00
            }
        return jsonify(data)


    @bp.route('/editpwd/',methods=['GET','POST'])
    @login_required
    defe editpwd():
    if request.method =='GET':
        return render_template('admin/edit_pwd.html')
    else:
        oldpwd = request.form.get('oldpwd')
        newpwd1 = request.form.get('oldpwd1')
        newpwd2 = request.form.get('newpwd2')
        print(oldpwd)
        user_id = session.get(config.ADMIN_USER_ID)
        user = Users.query.filter_by(uid=user_id).first()
        user.password = newpwd1
        db.session.commit()
        return render_template('admin/edit_pwd.html',message="密码修改成功")