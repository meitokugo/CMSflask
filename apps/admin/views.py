from flask import Blueprint, render_template, request, session, redirect, url_for, jsonify
from .models import Users
from .forms import LoginForm
from .decorators import login_required
from io import BytesIO
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


@bp.route('/logout/')
@login_required
def logout():
    del session[user_id]
    return redirect(url_for('admin.login'))


# 个人信息页视图
@bp.route('/profile/')
@login_required
def profile():
    if config.ADMIN_USER_ID in session:
        user_id = session.get(config.ADMIN_USER_ID)
        user = Users.query.get(user_id)
    return render_template('admin/profile.html', user=user)


# 核实校验密码
@bp.route('/checkpwd/')
# @login_required
def checkpwd():
    # user1 = request.args.get('username')
    oldpwd = request.args.get('oldpwd', '')
    # print(oldpwd)
    if config.ADMIN_USER_ID in session:
        user_id = session.get(config.ADMIN_USER_ID)
        # user = Users.query.filter_by(username='admin').first()#这里作了修改
        user = Users.query.filter(Users.uid == user_id).first()  # 这里作了修改
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


@bp.route('/editpwd/', methods=['GET', 'POST'])
@login_required
def editpwd():
    if request.method == 'GET':
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
        return render_template('admin/edit_pwd.html', message="密码修改成功")


def build_tree(data, p_id, level=0):
    """
    生成树菜单
    :param data:    数据
    :param p_id:    上级分类
    :param level:   当前级别
    :return:
    """
    tree = []
    for row in data:
        if row['parent_id'] == p_id:
            row['level'] = level
            child = build_tree(data, row['cat_id'], level + 1)
            row['child'] = []
            if child:
                row['child'] += child
            tree.append(row)

    return tree


# 生成分类
def build_table(data, parent_title='顶级菜单'):
    html = ''
    for row in data:
        splice = '├ '
        cat_id = row['cat_id']
        title = splice * row['level'] + row['cat_name']
        tr_td = """<option value={cat_id}>  {title}</option>
                                   """
        if row['child']:
            html += tr_td.format(class_name='top_menu', title=title, cat_id=cat_id)
            html += build_table(row['child'], row['cat_name'])
        else:
            html += tr_td.format(class_name='', title=title, cat_id=cat_id)
            # return html
    return html


# 添加分类
@bp.route('/article_cat_add/', methods=['GET', 'POST'])
@login_required
def article_cat_add():
    if request.method == 'GET':
        categorys = Articles_Cat.query.all()  # 取得所有分类
        list = []
        data = {}

        for cat in categorys:
            data = dict(cat_id=cat.cat_id, parent_id=cat.parent_id, cat_name=cat.cat_name)
            list.append(data)
        data = build_tree(list, 0, 0)
        print(data)
        # print(list)
        html = build_table(data, parent_title='顶级菜单')
        # print(html)
        return render_template('admin/article_cat.html', message=html)  # article_cat.html
    else:
        form = Article_cat(request.form)
        p = Pinyin()
        dir = request.form.get('dir')
        print(dir)
        if form.validate():
            parent_id = request.form.get('parent_id')
            cat_name = request.form.get('cat_name')
            dir = request.form.get('dir')
            check = request.form.get('check')
            if check:
                dir = request.form.get('cat_name')
                dir = p.get_pinyin(dir, '')
            else:
                if dir:
                    dir = request.form.get('dir')
                else:
                    dir = request.form.get('cat_name')
                    dir = p.get_pinyin(dir, '')
            keywords = request.form.get('keywords')
            description = request.form.get('description')
            cat_sort = request.form.get('cat_sort')
            status = request.form.get('status')
            insert = Articles_Cat(parent_id=parent_id, cat_name=cat_name, dir=dir, keywords=keywords,
                                  description=description, cat_sort=cat_sort, status=status)
            db.session.add(insert)
            db.session.commit()
            return redirect(url_for('admin.article_cat_list'))
        else:
            print("校验没有通过")
            return "校验没通过 "


# 栏目列表
@bp.route('/article_cat_list/', methods=['GET'])
@login_required
@admin_auth
def article_cat_list():
    if request.method == 'GET':
        categorys = Articles_Cat.query.all()  # 取得所有分类
        list = []
        data = {}

        for cat in categorys:
            data = dict(cat_id=cat.cat_id, parent_id=cat.parent_id, cat_name=cat.cat_name, description=cat.description,
                        dir=cat.dir, cat_sort=cat.cat_sort)
            list.append(data)
        data = build_tree(list, 0, 0)
        html = creat_cat_list(data, parent_title='顶级菜单')
        return render_template('admin/articel_cat_list.html', message=html)


@bp.route('/article_cat_edit/<id>/', methods=['GET', 'POST'])
@login_required
def article_cat_edit(id):
    if request.method == 'GET':
        cat_list = Articles_Cat.query.filter_by(cat_id=id).first()
        categorys = Articles_Cat.query.all()  # 取得所有分类
        list = []
        data = {}
        for cat in categorys:
            data = dict(cat_id=cat.cat_id, parent_id=cat.parent_id, cat_name=cat.cat_name)
            list.append(data)
        data = build_tree(list, 0, 0)
        html = build_table(data, parent_title='顶级菜单')
        return render_template('admin/artical_cat_edit.html', content=cat_list, message=html)
