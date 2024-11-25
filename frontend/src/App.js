import React, { useState } from 'react';
import LoginForm from './components/Login';
import Profile from './components/Profile';
// states
const App = () => {
    const [login, set_login] = useState(false);
    const login_handle = () => {
        set_login(true); // it set to true when the login is successful!
    };
    return (
        <div>
            {!login ? ( <LoginForm onLogin={login_handle} />) : ( <Profile />)}
        </div>
    );
};
export default App;
