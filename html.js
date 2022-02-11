export const changePassword = `
<!doctype html>
<html lang="en-US">
    <head>
        <meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
        <title>Reset Password!</title>
        <meta name="description" content="Reset Password Email">
        <style type="text/css">
            body {
                background: linear-gradient(90deg,#f64f59,#c471ed,#12c2e9);
                min-height: 100vh;
            }
            taable {
                background: linear-gradient(90deg,#f64f59,#c471ed,#12c2e9);
                min-height:100vh;
            }
            table {
                opacity: 1;
            }
            .button {
                background-color: #4CAF50; /* Green */
                margin-top: 45px;
                border: none;
                color: white;
                padding: 16px 32px;
                text-align: center;
                text-decoration: none;
                display: inline-block;
                font-size: 16px;
                margin: 4px 2px;
                transition-duration: 0.4s;
                cursor: pointer;
            }
            .button1 {
                background:#20e277;
                text-decoration:none !important;
                font-weight:500; 
                margin-top:45px; 
                color:#fff;
                text-transform:uppercase; 
                font-size:14px;
                padding:10px 134px;
                display:inline-block;
                color: white;
                border-radius:50px;
                background-color: #4CAF50;
                border: 2px solid #4CAF50;
                transition-duration: 0.5s;
            }
            
            .button1:hover {
                background-color: white; 
                transition-duration: 0.5s;
                color: black; 
            }
    
            input {
                width: 100%;
                padding: 12px 20px;
                border-radius: 5px;
                border: 2px solid #4CAF50;
                box-sizing: border-box;
                margin: 2px;
                transition-duration: 0.5s;
            }
            input:focus {
                border: 2px solid #555;
            }
            input:hover {
                transition-duration: 0.5s;
                border: 2px solid #555;
            }
            #long {
                transition-duration: 0.5s;
                margin: 8px auto 0;
            }
            #long:hover {
                box-shadow: 0 3px 10px rgb(0 0 0 / 0.2);
                transition-duration: 0.5s;
                margin: -8px auto 0;
            }
            a:hover {text-decoration: underline !important;}
        </style>
    </head>
    
    <body marginheight="0" topmargin="0" marginwidth="0" style="margin: 0px; background-color: #f2f3f8;" leftmargin="0">
        <!--100% body table-->
        <table cellspacing="0" border="0" cellpadding="0" id="aaa" width="100%" 
            style="@import url(https://fonts.googleapis.com/css?family=Rubik:300,400,500,700|Open+Sans:300,400,600,700); font-family: 'Open Sans', sans-serif;">
            <tr>
                <td>
                    <table style="max-width:670px;  margin:0 auto;" width="100%" border="0"
                        align="center" cellpadding="0" cellspacing="0">
                        <tr>
                            <td style="height:80px;">&nbsp;</td>
                        </tr>
                        <tr id="a4">
                            <td style="height:20px;">&nbsp;</td>
                        </tr>
                        <tr>
                            <td>
                                <table id="long" width="10%" border="0" align="center" cellpadding="0" cellspacing="0"
                                    style="max-width:670px;background:#fff; border-radius:20px; text-align:center;-webkit-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);-moz-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);box-shadow:0 6px 18px 0 rgba(0,0,0,.06);">
                                    <tr>
                                        <td style="height:80px;"></td>
                                    </tr>
                                    <tr>
                                        <td style="text-align:center;">
                                            <a href="https://www.nextflow.cloud" title="logo" target="_blank">
                                            <img width="60" src="https://i.ibb.co/hL4XZp2/android-chrome-192x192.png" title="logo" alt="logo">
                                            </a>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="height:80px;">&nbsp;</td>
                                    </tr>
                                    <tr>
                                        <td style="padding:0 35px;">
                                            <h1 style="color:#1e1e2d; font-weight:500; margin:0;font-size:32px;font-family:'Rubik',sans-serif;">Change password</h1>
                                            <span
                                                style="display:inline-block; vertical-align:middle; margin:29px  26px; border-bottom:1px solid #cecece; width:400px;"></span>
                                            <!-- <p style="color:#455056; font-size:15px;line-height:24px; margin:0;">
                                                We cannot simply send you your old password. A unique link to reset your
                                                password has been generated for you. To reset your password, click the
                                                following link and follow the instructions.
                                            </p> -->
                                            <table align="center">
                                                <tr>
                                                    <td>
                                                        <input type="password" name="old" require id="old" placeholder="Current Password">
                                                    </td>
                                                </tr>
                                                <tr>
                                                    <td>
                                                        <input type="password" name="password" required id="password" placeholder="New password" size="46">
                                                    </td>
                                                </tr>
                                                <tr>
                                                    <td>
                                                        <input type="password" name="confirm" required id="confirm" placeholder="Confirm Password">
                                                    </td>
                                                </tr>
                                            </table>
                                            <div>
                                                <label id="error" style="color: #f64f59; opacity: 0;">Empty password inputs are not allowed</label>
                                            </div>
                                            <button class="button1" id="submit">
                                                Change Password
                                            </button>
                                            <!-- <a href="javascript:void(0);" -->
                                                <!-- style="background:#20e277;text-decoration:none !important; font-weight:500; margin-top:45px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 34px;display:inline-block;border-radius:50px;">Reset -->
                                                <!-- Password</a> -->
                                            
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="height:100px;">&nbsp;</td>
                                    </tr>
                                </table>
                            </td>
                        <tr id="a2">
                            <td style="height:20px;">&nbsp;</td>
                        </tr>
                        <tr>
                            <td style="text-align:center;">
                                <p style="font-size:14px; color:rgba(255, 255, 255, 1); line-height:18px; margin:0 0 0;">&copy; 2022 Nextflow Technologies B.V. All rights reserved.</p>
                            </td>
                        </tr>
                        <tr id="a1">
                            <td style="height:80px;">&nbsp;</td>
                        </tr>
                    </table>
                </td>
            </tr>
            <tr>
                <!-- <td> -->
                    <!-- <p style="font-size:14px; color:rgba(255, 255, 255, 1); line-height:18px; margin:0 0 0;">&copy; 2022 Nextflow Technologies B.V. All rights reserved.</p> -->
                <!-- </td> -->
            </tr>
        </table>
        <!--/100% body table-->
        <script>
            let token = localStorage.getItem('token');
            if (token.trim() === '' || !token.trim()) {
                document.location = 'https://secure.nextflow.cloud';
            }
            let password = document.getElementById('password');
            let confirm = document.getElementById('confirm');
            let button = document.getElementById('submit');
            let error = document.getElementById('error');
            let oldpassword = document.getElementById('old');
            button.addEventListener('click', event => {
                if (password.value == '' || confirm.value == '' || oldpassword.value == '') {
                    error.textContent = "Empty password inputs are not allowed.";
                    error.style.opacity = '1'
                    return;
                }
                if (password.value !== confirm.value) {
                    error.textContent = "The new password is not equivalent to password confirm input.";
                    error.style.opacity = '1';
                    return;
                }
                error.style.opacity = '0'
                fetch('https://secure.nextflow.cloud/api/change_password', {
                    method: "POST",
                    body: JSON.stringify({ old: oldpassword.value, password: password.value }),
                    headers: {
                        "Content-Type": "application/json",
                        "authorization": JSON.stringify({ token: localStorage.getItem("token") })
                    },
                }).then(async res => {
                    if (res.status !== 200) {
                    error.textContent = await res.text();
                    error.style.opacity = '1';
                    } else {
                        document.location = 'https://secure.nextflow.cloud'
                    }
                })
            })
        </script>
    </body>
</html>
`;
export const forgot = `
<!doctype html>
<html lang="en-US">
    <head>
        <meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
        <title>Reset Password!</title>
        <meta name="description" content="Reset Password Email">
        <style type="text/css">
            body {
            background: linear-gradient(90deg,#f64f59,#c471ed,#12c2e9);
            min-height: 100vh;
            }
            taable {
            background: linear-gradient(90deg,#f64f59,#c471ed,#12c2e9);
            min-height:100vh;
            }
            table {
            opacity: 1;
            }
            .button {
            background-color: #4CAF50; /* Green */
            margin-top: 45px;
            border: none;
            color: white;
            padding: 16px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 4px 2px;
            transition-duration: 0.4s;
            cursor: pointer;
            }
            .button1 {
                background:#20e277;
                text-decoration:none !important;
                font-weight:500; 
                margin-top:45px; 
                color:#fff;
                text-transform:uppercase; 
                font-size:14px;
                padding:10px 134px;
                display:inline-block;
                color: white;
                border-radius:50px;
                background-color: #4CAF50;
                border: 2px solid #4CAF50;
                transition-duration: 0.5s;
            }
            
            .button1:hover {
                background-color: white; 
                transition-duration: 0.5s;
                color: black; 
            }

            input {
                width: 100%;
                padding: 12px 20px;
                border-radius: 5px;
                border: 2px solid #4CAF50;
                box-sizing: border-box;
                margin: 2px;
                transition-duration: 0.5s;
            }
            input:focus {
                border: 2px solid #555;
            }
            input:hover {
                transition-duration: 0.5s;
                border: 2px solid #555;
            }
            #long {
                transition-duration: 0.5s;
                margin: 8px auto 0;
            }
            #long:hover {
                box-shadow: 0 3px 10px rgb(0 0 0 / 0.2);
                transition-duration: 0.5s;
                margin: -8px auto 0;
            }
            a:hover {text-decoration: underline !important;}
        </style>
    </head>

    <body marginheight="0" topmargin="0" marginwidth="0" style="margin: 0px; background-color: #f2f3f8;" leftmargin="0">
        <!--100% body table-->
        <table cellspacing="0" border="0" cellpadding="0" id="aaa" width="100%" 
            style="@import url(https://fonts.googleapis.com/css?family=Rubik:300,400,500,700|Open+Sans:300,400,600,700); font-family: 'Open Sans', sans-serif;">
            <tr>
                <td>
                    <table style="max-width:670px;  margin:0 auto;" width="100%" border="0"
                        align="center" cellpadding="0" cellspacing="0">
                        <tr>
                            <td style="height:80px;">&nbsp;</td>
                        </tr>
                        <tr id="a4">
                            <td style="height:20px;">&nbsp;</td>
                        </tr>
                        <tr>
                            <td>
                                <table id="long" width="10%" border="0" align="center" cellpadding="0" cellspacing="0"
                                    style="max-width:670px;background:#fff; border-radius:20px; text-align:center;-webkit-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);-moz-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);box-shadow:0 6px 18px 0 rgba(0,0,0,.06);">
                                    <tr>
                                        <td style="height:80px;"></td>
                                    </tr>
                                    <tr>
                                        <td style="text-align:center;">
                                        <a href="https://www.nextflow.cloud" title="logo" target="_blank">
                                            <img width="60" src="https://i.ibb.co/hL4XZp2/android-chrome-192x192.png" title="logo" alt="logo">
                                        </a>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="height:80px;">&nbsp;</td>
                                    </tr>
                                    <tr>
                                        <td style="padding:0 35px;">
                                            <h1 style="color:#1e1e2d; font-weight:500; margin:0;font-size:32px;font-family:'Rubik',sans-serif;">Change password</h1>
                                            <span
                                                style="display:inline-block; vertical-align:middle; margin:29px  26px; border-bottom:1px solid #cecece; width:400px;"></span>
                                            <!-- <p style="color:#455056; font-size:15px;line-height:24px; margin:0;">
                                                We cannot simply send you your old password. A unique link to reset your
                                                password has been generated for you. To reset your password, click the
                                                following link and follow the instructions.
                                            </p> -->
                                            <table align="center">
                                                <tr>
                                                    <td>
                                                        <input type="password" name="password" required id="password" placeholder="New password" size="46">
                                                    </td>
                                                </tr>
                                                <tr>
                                                    <td>
                                                        <input type="password" name="confirm" required id="confirm" placeholder="Confirm Password">
                                                    </td>
                                                </tr>
                                            </table>
                                            <div>
                                                <label id="error" style="color: #f64f59; opacity: 0;">Empty password inputs are not allowed</label>
                                            </div>
                                            <button class="button1" id="submit">
                                                Change Password
                                            </button>
                                            <!-- <a href="javascript:void(0);" -->
                                                <!-- style="background:#20e277;text-decoration:none !important; font-weight:500; margin-top:45px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 34px;display:inline-block;border-radius:50px;">Reset -->
                                                <!-- Password</a> -->
                                            
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="height:100px;">&nbsp;</td>
                                    </tr>
                                </table>
                            </td>
                        <tr id="a2">
                            <td style="height:20px;">&nbsp;</td>
                        </tr>
                        <tr>
                            <td style="text-align:center;">
                                <p style="font-size:14px; color:rgba(255, 255, 255, 1); line-height:18px; margin:0 0 0;">&copy; 2022 Nextflow Technologies B.V. All rights reserved.</p>
                            </td>
                        </tr>
                        <tr id="a1">
                            <td style="height:80px;">&nbsp;</td>
                        </tr>
                    </table>
                </td>
            </tr>
            <tr>
                <!-- <td> -->
                    <!-- <p style="font-size:14px; color:rgba(255, 255, 255, 1); line-height:18px; margin:0 0 0;">&copy; 2022 Nextflow Technologies B.V. All rights reserved.</p> -->
                <!-- </td> -->
            </tr>
        </table>
        <!--/100% body table-->
        <script>
            let password = document.getElementById('password');
            let confirm = document.getElementById('confirm');
            let button = document.getElementById('submit');
            let error = document.getElementById('error');
            button.addEventListener('click', event => {
                if (password.value == '' || confirm.value == '') {
                    error.textContent = "Empty password inputs are not allowed.";
                    error.style.opacity = '1'
                    return;
                }
                if (password.value !== confirm.value) {
                    error.textContent = "The new password is not equivalent to password confirm input.";
                    error.style.opacity = '1';
                    return;
                }
                error.style.opacity = '0'
                fetch('https://secure.nextflow.cloud/api/reset/{req.params.code}', {
                    method: "POST",
                    body: JSON.stringify({ password: password.value }),
                    headers: {
                        "Content-Type": "application/json"
                    }
                }).then(async res => {
                if (res.status !== 200) {
                    error.textContent = await res.text();
                    error.style.opacity = '1';
                } else {
                    document.location = 'https://secure.nextflow.cloud'
                }
                })
            })
        </script>
    </body>
</html>
`;