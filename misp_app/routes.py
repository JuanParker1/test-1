import os
import datetime
import secrets
from itsdangerous.url_safe import URLSafeTimedSerializer
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort, jsonify
from misp_app import app, db, bcrypt, mail
from misp_app.forms import RegistrationForm, LoginForm, UpdateAccountForm, AddAttributes,feedfromMisp, UpdateAttributes,AddClient, UpdateClient, search, RequestResetForm, ResetPasswordForm
from misp_app.models import User, Attributes, Clients, Events,Attributesaccount, Results
from flask_login import login_user, current_user, logout_user, login_required
from misp_app.fonctions import IOCcount, QRadarCheck, Misp, qradar, feedtable, manualqradarfeeds, EventToMisp, addtoreferenceSet
import concurrent.futures
from flask_mail import Message



@app.route("/")
@app.route('/events' , methods = ['GET','POST'])
@login_required
def AllEvents():
    users = Events.query.all()
    variable = Attributesaccount.query.first()
    variable = [variable.URLs,variable.Domains,variable.IPs,variable.SHA256,variable.SHA1,variable.MD5]
    return render_template('listofevents.html', title='events', var = variable,users=users)

@app.route('/home')
def home():
    users = Attributes.query.all()
    variable = Attributesaccount.query.first()
    variable = [variable.URLs,variable.Domains,variable.IPs,variable.SHA256,variable.SHA1,variable.MD5]
    return render_template('server_table.html', title='List Attributes',users=users,var=variable)


@app.route("/Clients", methods= ['GET', 'POST'])
@login_required
def Client():
    if current_user.is_admin == 'true':
        var8 = Clients.query.all()
        return render_template('client.html', title='Clients', Attribute = var8)
    else:
        flash('You have to be admin to access clients page', 'danger')
        return redirect(url_for('home'))


    
@app.route("/feeds", methods= ['GET', 'POST'])
@login_required
def feedFromMisp():
    form = feedfromMisp()
    var50 = Clients.query.all()
    if len(var50) != 0:
        worker = len(var50)
    else:
        worker=1
    if current_user.is_admin == 'true':
        if form.validate_on_submit():
            iocs = Misp(form.Category.data, form.Type.data, form.Last.data)
            Results.query.delete()
            if iocs == 'Unexpected error':
                flash('You have a problem in Misp ', 'danger')
                return redirect(url_for('feedFromMisp'))
            elif form.send.data == True:
                feedtable(iocs, form.Category.data, form.Type.data)
                with concurrent.futures.ThreadPoolExecutor(worker) as executor:
                    futures = []
                    for add in var50:
                        futures.append(executor.submit(qradar, Iocs=iocs, Client=add.q_ip, Reference_set=form.Type.data, SEC_token=add.q_token, Client_name=add.clientname, Client_status=add.status))
                    for future in concurrent.futures.as_completed(futures):
                        rus = future.result()
                        result = Results(client=rus["client"],ipaddress=rus["ip address"],feedstatus=rus["feedstatus"])
                        db.session.add(result)
                        db.session.commit() 
                    flash('{} att has been add to client'.format(len(iocs)), 'success')
                    return render_template('feeds.html', title='feedss', form=form)
            elif form.send.data == False:
                with concurrent.futures.ThreadPoolExecutor(worker) as executor:
                    futures = []
                    for add in var50:
                        futures.append(executor.submit(qradar, Iocs=iocs, Client=add.q_ip, Reference_set=form.Type.data, SEC_token=add.q_token, Client_name=add.clientname, Client_status=add.status))
                    for future in concurrent.futures.as_completed(futures):
                        rus = future.result()
                        result = Results(client=rus["client"],ipaddress=rus["ip address"],feedstatus=rus["feedstatus"])
                        db.session.add(client2)
                        db.session.commit()
                    flash('{} att has been add to client'.format(len(iocs)), 'info')
                    return render_template('feeds.html', title='feedss', form=form)        
    else:
        flash('You have to be admin to access this page', 'danger')
        return redirect(url_for('AllEvents'))
    return render_template('feeds.html', title='feedss', form=form)



@app.route("/AddClients", methods= ['GET', 'POST'])
@login_required
def AddClients():
    form = AddClient()
    if current_user.is_admin == 'true':
        if form.validate_on_submit():
            client2 = Clients(clientname=form.clientname.data,q_ip=form.q_ip.data,q_token=form.q_token.data,status='Down')
            db.session.add(client2)
            db.session.commit()            
            flash('the client  has been Added!', 'success')
        return render_template('Addclient.html', title='Add client', form=form)
    else:
        flash('You have to be admin to access this page', 'danger')
        return redirect(url_for('AllEvents'))



@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('AllEvents'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('AllEvents'))
        else:
            flash('Login Unsuccessful. Please check email or password', 'danger')
    return render_template('login.html', title='Login', form=form)



@app.route("/register", methods=['GET', 'POST'])
@login_required
def register():
    form = RegistrationForm()
    if current_user.is_admin == 'true':
        if form.validate_on_submit():
            if form.privilage.data == True:
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                user = User(username=form.username.data, email=form.email.data, password=hashed_password,is_admin='true')
                db.session.add(user)
                db.session.commit()
                flash('the admin account has been created!', 'success')
                return redirect(url_for('register'))
            else:
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                user = User(username=form.username.data, email=form.email.data, password=hashed_password,is_admin='false')
                db.session.add(user)
                db.session.commit()
                flash('the simple user account has been created!', 'success')
                return redirect(url_for('register'))
    else:
        flash('You have to be admin to access this page', 'danger')
        return redirect(url_for('AllEvents'))
    return render_template('register.html', title='Register', form=form)



@app.route("/Add_Attributes", methods=['GET', 'POST'])
@login_required
def Add_Attributes():
    form = AddAttributes()
    if form.validate_on_submit():
        if form.send.data == True:
            var80 = Clients.query.all()
            worker = len(var80)
            if form.Comment.data:
                Att = Attributes(event_id=form.Eventid.data, Category=form.Category.data, Type=form.Type.data, Value=form.Value.data, Creator_user=current_user.username, Comment=form.Comment.data, user_id=current_user.id)
            else:
                Att = Attributes(event_id=form.Eventid.data, Category=form.Category.data, Type=form.Type.data, Value=form.Value.data, Creator_user=current_user.username, user_id=current_user.id)
            db.session.add(Att)
            db.session.commit()
            Results.query.delete()
            with concurrent.futures.ThreadPoolExecutor(worker) as executor:
                futures = []
                Rus =[]
                for add in var80:
                    futures.append(executor.submit(manualqradarfeeds, Iocs=form.Value.data, Client=add.q_ip, Reference_set=form.Type.data, SEC_token=add.q_token, Client_name=add.clientname, Client_status=add.status))
                for future in concurrent.futures.as_completed(futures):
                    rus = future.result()
                    result = Results(client=rus["client"],ipaddress=rus["ip address"],feedstatus=rus["feedstatus"])
                    db.session.add(result)
                    db.session.commit()
        else:
            if form.Comment.data:
                Att = Attributes(event_id=form.Eventid.data, Category=form.Category.data, Type=form.Type.data, Value=form.Value.data, Creator_user=current_user.username, Comment=form.Comment.data, user_id=current_user.id)
            else:
                Att = Attributes(event_id=form.Eventid.data, Category=form.Category.data, Type=form.Type.data, Value=form.Value.data, Creator_user=current_user.username, user_id=current_user.id)
            db.session.add(Att)
            db.session.commit()

        flash('The Attribute has been added successfully', 'success')
        redirect(url_for('Add_Attributes'))
    
    return render_template('Add_Attributes.html', title='Register', form=form, legend='Add Attribute')



@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))




def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn



@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.new_password.data:
            current_user.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account', image_file=image_file, form=form)

@app.route("/home/<int:att_id>/delete", methods=['POST'])
@login_required
def delete_att(att_id):
    var3 = Attributes.query.get_or_404(att_id)
    if var3.author != current_user:
        abort(403)
    db.session.delete(var3)
    db.session.commit()
    flash('Your att has been deleted!', 'success')
    return redirect(url_for('home'))



@app.route("/home/<int:att_id>/update", methods=['GET', 'POST'])
@login_required
def update_att(att_id):
    var2 = Attributes.query.get_or_404(att_id)
    form = UpdateAttributes()
    form.update_att_id.data = att_id
    form.Eventid.data = var2.has_Attributes.id 
    if form.validate_on_submit():
        if var2.author != current_user:
            abort(403)
        var2.Category = form.Category.data
        var2.Type=form.Type.data
        var2.Value=form.Value.data
        var2.Comment=form.Comment.data
        db.session.commit()
        flash('Your att has been updated!', 'success')
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.Category.data = var2.Category
        form.Type.data = var2.Type
        form.Value.data =var2.Value
        form.Comment.data = var2.Comment

    return render_template('Add_Attributes.html', title='Update Post',form=form, legend='Update Att',var2=var2,current_user=current_user)



@app.route("/Clients/<int:client_id>/delete", methods=['POST'])
@login_required
def delete_client(client_id):
    var7 = Clients.query.get_or_404(client_id)
    if current_user.is_admin == 'true':
        abort(403)
    db.session.delete(var7)
    db.session.commit()
    flash('Your client has been deleted!', 'success')
    return redirect(url_for('Client'))



@app.route("/Clients/<int:client_id>/update", methods=['GET', 'POST'])
@login_required
def update_client(client_id):
    var9 = Clients.query.get_or_404(client_id)
    if current_user.is_admin == 'true':
        abort(403)
    form = UpdateClient()
    if form.validate_on_submit():
        var9.clientname = form.clientname.data
        var9.q_ip=form.q_ip.data
        var9.q_token=form.q_token.data
        db.session.commit()
        flash('Your att has been updated!', 'success')
        return redirect(url_for('Client'))
    elif request.method == 'GET':
        form.clientname.data = var9.clientname
        form.q_ip.data = var9.q_ip
        form.q_token.data =var9.q_token

    return render_template('UpdateClient.html', title='Update Client',form=form, clientid=client_id, legend='Update Client')


@app.route("/home/delete_all", methods=['POST'])
@login_required
def delete_att_all():
    var3 = Attributes.query.filter_by(user_id=current_user.id).all()
    for cd in var3:
        db.session.delete(cd)
        db.session.commit()
    flash('all Attributes created by {} has been deleted!'.format(current_user.username), 'success')
    return redirect(url_for('home'))

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
''' 

    mail.send(msg)



@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    userid = s.loads(token)['user_id']
    if (current_user.is_authenticated and current_user.id == userid) :
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)



@app.route('/Addevent' , methods = ['GET','POST'])
@login_required
def Addevent():
    last_id = Events.query.order_by(Events.id.desc()).first()
    if last_id:
        lastid = last_id.id + 1
    else:
        lastid = 1
    if request.method == 'GET':
        return render_template('Addevents.html',lastid=lastid,Creator_name=current_user.username)
 
    if request.method == 'POST':
        event_name = request.form['event_name']
        Creator_org = request.form['Creator_org']
        Owner_org = request.form['Owner_org']
        Creator_user = current_user.username
        tags = request.form['tags']
        tags = tags.split(",")
        tags = str(tags)
        date = request.form['date']
        date = date.split("/")
        st="-"
        date=st.join(date)+" 00:00:00"
        date=datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
        Threat_Level = request.form['Threat_Level']
        Distribution = request.form['Distribution']
        Analysis = request.form['Analysis']
        comment = request.form['comment']
        try:
            AddtoReferenceSet = request.form['AddtoReferenceSet']
        except Exception:
            AddtoReferenceSet = "false"
        try:
            AddtoMisp = request.form['AddtoMisp']
        except Exception:
            AddtoMisp = 'false'

        Event = Events(
            event_name=event_name,
            Creator_org=Creator_org,
            Owner_org=Owner_org,
            Creator_user=Creator_user,
            Tags=tags,
            Date=date,
            Threat_Level=Threat_Level,
            Distribution = Distribution,
            Analysis=Analysis,
            Comment=comment
        )
        db.session.add(Event)
        db.session.commit()
        flash('The event has been Add successfully', 'success')
        return redirect(url_for('event',eventid=lastid))



@app.route("/<int:lastid>/Add_Attributes", methods=['GET', 'POST'])
@login_required
def Add_Attributetoevent(lastid):
    form = AddAttributes()
    form.Eventid.data = lastid
    testid = Events.query.filter_by(id=lastid).first()
    if testid is None:
        users = Events.query.all()
        variable = Attributesaccount.query.first()
        variable = [variable.URLs,variable.Domains,variable.IPs,variable.SHA256,variable.SHA1,variable.MD5]
        flash('there is no event with id {}'.format(lastid), 'warning')
        return render_template('listofevents.html',var=variable,users=users)
    if form.validate_on_submit():
        if testid.Creator_user != current_user.username:
            abort(403)
        if form.Comment.data:
            Att = Attributes(Category=form.Category.data, Type=form.Type.data, Value=form.Value.data, Creator_user=current_user.username, Comment=form.Comment.data, user_id=current_user.id, event_id=lastid)
        else:
            Att = Attributes(Category=form.Category.data, Type=form.Type.data, Value=form.Value.data, Creator_user=current_user.username, user_id=current_user.id, event_id=lastid)
        db.session.add(Att)
        db.session.commit()
        flash('The Attribute has been added successfully', 'success')
        return redirect(url_for('event',eventid=lastid))
    
    return render_template('Add_Attributes.html', form=form, legend='Add Attribute')

@app.route('/event/<int:eventid>' , methods = ['GET','POST'])
@login_required
def event(eventid):
    form = AddAttributes()
    form.Eventid.data = eventid
    eventdata = Events.query.get_or_404(eventid)
    event_data = Events.query.get_or_404(eventid)
    tags = eventdata.Tags
    tags=tags.replace("'", '')
    tags=tags.replace("[", '')
    tags=tags.replace("]", '')
    eventdata = {"event_id":eventdata.id,"event_name":eventdata.event_name,"Creator_org":eventdata.Creator_org,"Owner_org":eventdata.Owner_org,"Creator_user":eventdata.Creator_user,"tags":tags,"Date":eventdata.Date.strftime("%Y-%m-%d"),"Threat_Level":eventdata.Threat_Level,"Distribution":eventdata.Distribution,"Analysis":eventdata.Analysis,"Comment":eventdata.Comment,"Attributes":eventdata.Attributes}
    if request.method == 'GET':
        return render_template('event.html',lastid=eventid,form=form,eventdata=eventdata)
 
    if request.method == 'POST':
        if event_data.has_events != current_user:
            abort(403)
        event_data.event_name = request.form['event_name']
        event_data.Creator_org = request.form['Creator_org']
        event_data.Owner_org = request.form['Owner_org']
        event_data.Creator_user = current_user.username
        tags = request.form['tags']
        tags = tags.split(",")
        tags = str(tags)
        event_data.Tags = tags
        date = request.form['date']
        date = date.split("/")
        st="-"
        date=st.join(date)+" 00:00:00"
        event_data.Date=datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
        event_data.Threat_Level = request.form['Threat_Level']
        event_data.Distribution = request.form['Distribution']
        event_data.Analysis = request.form['Analysis']
        event_data.Comment = request.form['comment']
        db.session.commit()
        try:
            AddtoReferenceSet = request.form['AddtoReferenceSet']
        except Exception:
            AddtoReferenceSet = False
        try:
            AddtoMisp = request.form['AddtoMisp']
        except Exception:
            AddtoMisp = False
        true = True
        false= False
        distribution = {'Your Organisation Only':'0','This Community Only':'1','Connected Communities':'2','All Communities':'3','Sharing Group':'4'}
        analysis = {'Initial':'0','Ongoing':'1','Complete':'2'}
        threat_level_id ={'Undefined':'4','Low':'3','Medium':'2','High':'1'}
        if AddtoMisp != False:
            tagss = event_data.Tags
            tagss=tagss.replace("'", '')
            tagss=tagss.replace("[", '')
            tagss=tagss.replace("]", '')
            tagss=tagss.replace(" ", '')
            tagss = list(tagss.split(","))
            dicttags={'spam': '#49f1ed', 'phishing': '#c1e21c', 'virus': '#42933e', 'worm': '#f24722', 'ransomware': '#fea700', 'trojan-malware': '#42933e', 'spyware-rat': '#008e63', 'rootkit': '#56b352', 'dialer': '#bf0dcc', 'scanner': '#ff0000', 'sniffing': '#372500', 'social-engineering': '#36a013', 'exploit-known-vuln': '#ff9f0f', 'login-attempts': '#595757', 'new-attack-signature': '#882d0e', 'privileged-account-compromise': '#5fb4b2', 'unprivileged-account-compromise': '#f1ee1d', 'botnet-member': '#00fff3', 'domain-compromise': '#777174', 'violence': '#991515', 'application-compromise': '#00809c', 'dos': '#f82378', 'ddos': '#ff8a00', 'sabotage': '#0f4d00', 'outage': '#585483', 'Unauthorised-information-access': '#008ba9', 'Unauthorised-information-modification': '#ef7f5c', 'copyright': '#850048', 'masquerade': '#ef7f5c', 'vulnerable-service': '#001d3f', 'regulator': '#540b39', 'standard': '#6772d6', 'security-policy': '#37d4e6', 'other-conformity': '#6772d6', 'harmful-speech': '#cb57f8'}
            tags_var = []
            att_var = []
            event_att  = Attributes.query.filter_by(event_id=eventid).all()
            for  EA in event_att:
                event_Att_data = {'type': EA.Type,'category': EA.Category,'to_ids': False,'distribution': '0','comment': EA.Comment,'value': EA.Value,}
                att_var.append(event_Att_data)
            for ta in tagss:
                u = {"exportable": True,"colour":dicttags[ta],"name":ta}
                tags_var.append(u)


            json_data = {
                'Event': {
                    'date': event_data.Date.strftime("%Y-%m-%d"),
                    'threat_level_id': threat_level_id[event_data.Threat_Level],
                    'info': event_data.event_name,
                    'published': False,
                    'analysis': analysis[event_data.Analysis],
                    'distribution': distribution[event_data.Distribution],
                    "Org": {
                        "id": "28",
                        "name": "Dataprotect",
                        "uuid": "bf351dc2-ea29-41f6-992e-03c1696d6a64"
                       },
                    "Orgc": {
                        "id": "2",
                        "name": "CIRCL",
                        "uuid": "55f6ea5e-2c60-40e5-964f-47a8950d210f"
                       },
                    'Attribute': att_var,
                    "Tag": tags_var
                                },
            }

            EventToMisp(json_data)
        if AddtoReferenceSet != False:
            var55 = Clients.query.all()
            Results.query.delete()
            if len(var55) != 0:
                worker = len(var55)
            else:
                worker=1
            att_var2 = []
            event_Att_data ={}
            event_att2  = Attributes.query.filter_by(event_id=eventid).all()
            for  EA in event_att2:
                event_Att_data = {'type': EA.Type, 'value': EA.Value}
                att_var2.append(event_Att_data)
            with concurrent.futures.ThreadPoolExecutor(worker) as executor:
                futures = []
                Rus =[]
                for add in var55:
                    futures.append(executor.submit(addtoreferenceSet, Iocs=att_var2, Client=add.q_ip, SEC_token=add.q_token, Client_name=add.clientname, Client_status=add.status))
                for future in concurrent.futures.as_completed(futures):
                    rus = future.result()
                    result = Results(client=rus["client"],ipaddress=rus["ip address"],feedstatus=rus["feedstatus"])
                    db.session.add(result)
                    db.session.commit()
        flash('the event has been added', 'success')
        return redirect(url_for('event',eventid=eventid))

@app.route('/getAttributes/<category>' , methods = ['GET','POST'])
@login_required
def getAttributes(category):
    category_type_mapping ={"Internal reference":["text","link","comment","other","hex","anonymised","git-commit-id"],"Antivirus detection":["link","comment","text","hex","attachment","other","anonymised"],"Payload delivery":["md5","sha1","sha224","sha256","sha384","sha512","sha512/224","sha512/256","sha3-224","sha3-256","sha3-384","sha3-512","ssdeep","imphash","telfhash","impfuzzy","authentihash","vhash","pehash","tlsh","cdhash","filename","filename|md5","filename|sha1","filename|sha224","filename|sha256","filename|sha384","filename|sha512","filename|sha512/224","filename|sha512/256","filename|sha3-224","filename|sha3-256","filename|sha3-384","filename|sha3-512","filename|authentihash","filename|vhash","filename|ssdeep","filename|tlsh","filename|imphash","filename|impfuzzy","filename|pehash","mac-address","mac-eui-64","ip-src","ip-dst","ip-dst|port","ip-src|port","hostname","domain","email","email-src","email-dst","email-subject","email-attachment","email-body","url","user-agent","AS","pattern-in-file","pattern-in-traffic","filename-pattern","stix2-pattern","yara","sigma","mime-type","attachment","malware-sample","link","malware-type","comment","text","hex","vulnerability","cpe","weakness","x509-fingerprint-sha1","x509-fingerprint-md5","x509-fingerprint-sha256","ja3-fingerprint-md5","jarm-fingerprint","hassh-md5","hasshserver-md5","other","hostname|port","email-dst-display-name","email-src-display-name","email-header","email-reply-to","email-x-mailer","email-mime-boundary","email-thread-index","email-message-id","mobile-application-id","chrome-extension-id","whois-registrant-email","anonymised"],"Artifacts dropped":["md5","sha1","sha224","sha256","sha384","sha512","filename","filename|md5","filename|sha1","filename|sha224","filename|sha256","filename|sha384","filename|sha512","pattern-in-file","pattern-in-memory","filename-pattern","yara","attachment","comment","text","hex","cookie","mime-type","anonymised","others"],"Payload installation":["md5","sha1","sha224","sha256","sha384","sha512","filename","filename|md5","filename|sha1","filename|sha224","filename|sha256","filename|sha384","filename|sha512","pattern-in-file","pattern-in-memory","filename-pattern","yara","vulnerability","weakness","attachment","malware-sample","malware-type","comment","text","hex","other","mime-type","anonymised"],"Network activity":["ip-src","ip-dst","ip-dst|port","ip-src|port","port","hostname","domain","domain|ip","mac-address","email","email-dst","email-src","eppn","url","uri","http-method","snort","pattern-in-file","filename-pattern","pattern-in-traffic","attachment","comment","text","hassh-md5","other","hex","cookie","hostname|port","zeek","anonymised","email-subject"],"External analysis":["md5","sha1","sha224","sha256","sha384","sha512","filename","filename|md5","filename|sha1","filename|sha256","ip-src","ip-dst","mac-address","hostname","domain","url","snort","zeek","bro","pattern-in-file","pattern-in-traffic","vulnerability","link","comment","text","weakness","other"]}
    dataArray = category_type_mapping[category]
    return jsonify({'Attributes' : dataArray})




@app.route("/event/<int:eventid>/delete", methods=['POST'])
@login_required
def delete_event(eventid):
    var7 = Events.query.get_or_404(eventid)
    if current_user.username != var7.Creator_user:
        abort(403)
    db.session.delete(var7)
    db.session.commit()
    flash('the event id {} has been deleted!'.format(eventid), 'success')
    return redirect(url_for('AllEvents'))

@app.route('/feedsAtt/<category>' , methods = ['GET','POST'])
@login_required
def feedsAtt(category):
    category_type_mapping ={"Antivirus detection":["link","text","hex"],"Payload delivery":["md5","sha1","sha256"],"Artifacts dropped":["md5","sha1","sha256","sha384","sha512","filename"],"External analysis":["md5","sha1","sha224","sha256","sha384","sha512","filename"],"Network activity":["ip-src","ip-dst","ip-dst|port","ip-src|port","port","hostname","domain","url"]}
    dataArray = category_type_mapping[category]
    return jsonify({'Attributes' : dataArray})

@app.route('/Ruselts' , methods = ['GET','POST'])
@login_required
def Ruselts():
    if current_user.is_admin != 'true':
        abort(403)
    var123 = Results.query.all()
    return render_template('results.html', title='Feeds Results', results=var123)
