import React, { useEffect, useState } from 'react';
import logo from './logo.svg';
import './App.css';
// import { BrowserRouter as Router, Route, Link } from 'react-router-dom';
import { Button, Input, Form, Switch } from 'antd';
// import { Layout, Menu, Breadcrumb, Icon } from 'antd';
import {fadeInRight} from 'react-animations';
import styled, { keyframes } from 'styled-components';
import { useLocation } from 'react-router-dom';
const fadeText = keyframes`${fadeInRight}`;

const Fade = styled.div`
  animation: 1s ${fadeText};
`;


const App = () => {
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [stage, setStage] = useState("email");
  const [fade, setFade] = useState();
  const [submit, setSubmit] = useState();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [continueToken, setContinueToken] = useState(localStorage.getItem("token"));
  const [token, setToken] = useState("");
  const [persist, setPersist] = useState(false);
  const [checked, setChecked] = useState(false);
  
  /*
  render() {
    return (
      <Router>
        <div className="Main">
          <Route path="/" exact component={Home} />
          <Route path="/authenticate" component={Au} />
        </div>
      </Router>
    );
  }*/
    
  const login = async () => {
    if (stage === "email") {
      if (!email.trim()) {
        setError("Email is blank");
        return;
      }
      var emailRegex = /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/g;
      var match = email.trim().match(emailRegex);
      if (!match || match.length !== 1) {
        setError("Invalid email");
        return;
      }
      setLoading(true);
      setEmail(match[0]);

      var request = await Promise.race([fetch('/api/login', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
        }, 
        body: JSON.stringify({
          email
        })
      }), new Promise(r => setTimeout(r, 5000))]);
      await new Promise(r => setTimeout(r, 500));
      if (!request) {
        console.error("[ERROR] Server timed out");
        setError("Server timed out");
        setLoading(false);
        return;
      }
      if (!request.ok) {
        console.error(`[ERROR] Server returned status code ${request.status}`);
        setError(`Server returned status code ${request.status}`);
        setLoading(false);
        if (request.status === 401) {
          console.error("[ERROR] Invalid email");
          setError("There is no account with that email. Did you make a typo?");
        }
        if (request.status === 429) {
          console.error("[ERROR] Rate limited");
          setError("Whoa there, chill out. You seem to be logging in too quickly.");
        }
        return;
      }
      var response = await request.json();
      console.log("[LOG] Login response: ", response); 
      setContinueToken(response.continueToken);
      
      setLoading(false);
      fade.style.animation = `1s fadeout`;
      await new Promise(r => setTimeout(r, 1000));
      setStage("password");
      fade.style.animation = "";
    } else if (stage === "password") {
      if (!password.trim()) {
        setError("Password is blank");
        return;
      }
      setLoading(true);
      
      var request = await Promise.race([fetch('/api/login/stage2', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          }, 
        body: JSON.stringify({
          continueToken,
          password,
          persist
        })
      }), new Promise(r => setTimeout(r, 10000))]);
      await new Promise(r => setTimeout(r, 500));
      if (!request) {
        console.error("[ERROR] Server timed out");
        setError("Server timed out");
        setLoading(false);
        return;
      }
      
      if (!request.ok) {
        console.error(`[ERROR] Server returned status code ${request.status}`);
        setError(`Server returned status code ${request.status}`);
        setLoading(false);
        if (request.status === 401) {
          console.error("[ERROR] Invalid password");
          setError("The password is incorrect. Did you make a typo?");
        }
        if (request.status === 403) {
          console.error("[ERROR] Session expired");
          fade.style.animation = `1s fadeout`;
          await new Promise(r => setTimeout(r, 1000));
          setStage("email");
          setError("Hmm, you seem to have waited too long to log in. Please try again.");
          fade.style.animation = "";
        }
        if (request.status === 429) {
          console.error("[ERROR] Rate limited");
          setError("Whoa there, chill out. You seem to be logging in too quickly.");
        }
        return;
      }
      var response = await request.json();
      console.log("[LOG] Login response: ", response);
      setToken(response.token);
      // localStorage.setItem('token', rs.token);
      // localStorage.setItem('isLoggedIn', true);
      // window.location.href = '/';
      
      setLoading(false);
      fade.style.animation = `1s fadeout`;
      await new Promise(r => setTimeout(r, 1000));
      setStage("2fa");
      fade.style.animation = "";
    } else if (stage === "2fa") {
      //submit 2fa
      setLoading(false);
      setStage("done");
    } else if (stage === "done") {
      // continue to destination
      
    }
    
  }
  const press = e => {      
    if (e.keyCode === 13) {      
      submit.click();   
    }  
  }
  const checkToken = async () => {
    if (continueToken) {
      var r = await fetch("/api/validate", {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
        }, 
        body: JSON.stringify({
          token: continueToken
        })
      });
      if (r.ok) setStage("skip");
      else setChecked(true);
    } else {
      setChecked(true);
    }
  }
  useEffect(() => checkToken(), []);
  
    
  var page = (
    <div className="main">
      <div className="inner">
        <Form>
          {(() => {
            if (stage === "email") {
              return (<Fade ref={node => setFade(node)}>
              <h1>Log in</h1>
  
              
              <div className="inside">  
                  <label>Email</label>
                  <Input type={"email"} disabled={loading} placeholder="Enter email" onKeyDown={press} value={email} onChange={v => setEmail(v.target.value)}></Input>
              </div>
              <div className="inside">
                <Button type="primary" shape="round" onClick={login} loading={loading} ref={node => setSubmit(node)}>Next</Button>
              </div>
              
              <p className="inside">
                  Forgot <a href="#">email?</a>
                  <br />
                  Don't have an account? <a href="/register">Register</a>
              </p>
              <p className='inside'>
                
              </p>
              
              <p className='inside error'>
                {error}
              </p>
            </Fade>)
            } else if (stage === "password") {
              return (<Fade ref={node => setFade(node)}>
              <h1>Log in</h1>
  
              <div className="inside">
                  <label>Password</label>
                  <Input type={"password"} placeholder="Enter password" onKeyDown={press} value={password} onChange={v => setPassword(v.target.value)}></Input>
              </div>
  
              <div className="inside">
                <Switch checked={persist} onChange={v => setPersist(v)} />
                <label> Stay signed in</label>
                <br />
                <br />
                <Button type="primary" shape="round" onClick={login} loading={loading} ref={node => setSubmit(node)}>Next</Button>
              </div>
  
              
              <p className="inside">
                  Forgot <a href="#">password?</a>
              </p>
              <p className='inside error'>
                {error}
              </p>
            </Fade>)
            } else if (stage === "2fa") {
              return (<Fade ref={node => setFade(node)}>
              <h1>[TEMPORARILY DISABLED - CLICK NEXT TO CONTINUE] One more thing! Enter your two-factor authentication code</h1>
  
              
              <div className="inside">  
                  <label>Code</label>
                  <Input type={"text"} placeholder="Enter code" onKeyDown={press}></Input>
              </div>
  
              <div className="inside">
                <Button type="primary" shape="round" onClick={login} loading={loading} ref={node => setSubmit(node)}>Log in</Button>
              </div>
  
              <p className='inside error'>
                {error}
              </p>
            </Fade> )
            } else if (stage === "done") {
              localStorage.setItem("token", token);
              setTimeout(() => {
                var getContinueUrl = new URLSearchParams(window.location.search).get("continue");
                window.location.href = getContinueUrl ? getContinueUrl : "https://nextflow.cloud";
              }, 1000);
              return (<Fade ref={node => setFade(node)}>
              <h1>Continue</h1>
              <div className="inside">  
                  <label>You have been logged in and are being redirected to your destination.</label>
              </div>
              <p className='inside error'>
                {error}
              </p>
            </Fade> )
            } else if (stage === "skip") {
              setTimeout(() => {
                var getContinueUrl = new URLSearchParams(window.location.search).get("continue");
                window.location.href = getContinueUrl ? getContinueUrl : "https://nextflow.cloud";
              }, 3000);
              return (<Fade ref={node => setFade(node)}>
              <h1>Continue</h1>
              <div className="inside">  
                  <label>You are already logged in and being redirected to your destination.</label>
              </div>
              <p className='inside error'>
                {error}
              </p>
            </Fade>)
            }
          })()}
          
        </Form>
      </div>
      <div className="footer">
        <p>Copyright &copy; 2022 Nextflow Technologies B.V. All rights reserved.</p>
      </div>
      <div className="mobile">
        <p>This app is not natively supported on mobile yet. Please check back later, we're working on it! ;)</p>
      </div>
    </div>
  );
  return checked ? page : (<div />);
}

export default App;
