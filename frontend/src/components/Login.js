import React, { useState } from 'react';
import './Login.css'; //importing css file for styling
// this are the states for form fields
const Login = ({ onLogin }) => {
    const [username, setUsername]= useState('');
    const [password, setPassword]= useState('');
    const [error, setError] = useState('');
    // function for handling form submission
    const handleSubmit= async(e)=> {
        e.preventDefault();
        setError('');
        try {
            const res = await fetch('http://localhost:5000/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ username, password }),
            });
            if (res.ok) {
                onLogin();
            } else {
                const errorText = await res.text();
                setError(errorText || 'Login is Failed');
            }
        } catch (err) {
            setError('NETWORK EROR !');
        }
    };
    return (
        <div>
            <h2>Login</h2>
            {error && <div>{error}</div>}
            <form onSubmit={handleSubmit}>
                <input type="text" placeholder="USERNAME OR EMAIL" value={username} onChange={(e) => setUsername(e.target.value)}required/>
                <input type="password" placeholder="PASSWORD" value={password} onChange={(e) => setPassword(e.target.value)} required/>
                <button type="submit">Login</button>
            </form>
        </div>
    );
};
export default Login;
