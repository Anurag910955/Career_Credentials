import React, { useState, useEffect } from 'react';
import Task from './Task';
import './Profile.css'; //importing css file for styling
// states
const Profile = () => {
    const [profile, setprofile] = useState({});
    const [editable, seteditable] = useState(false);
    const [showtaskdialog, setshowtaskdialog] = useState(false);
    const [newpassword, setnewpassword] = useState('');
    const [passwordmessage, setpasswordmessage] = useState('');

    useEffect(() => {
        fetch('http://localhost:5000/api/profile', { credentials: 'include' })
            .then((res) => res.json())
            .then((data) => setprofile(data));
    }, []);

    // for sending put request to server for updating user detail (saving user profile)
    const handleSave = async () => {
        await fetch('http://localhost:5000/api/profile', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(profile),
        });
        seteditable(false);
    };
    // for sending put request to server for updating user password
    const handleUpdatePassword = async () => {
        try {
            const res = await fetch('http://localhost:5000/api/profile/password', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ new_password: newpassword }),
            });
            if (res.ok) {
                setpasswordmessage('Password Updated');
            } else {
                const errorMessage = await res.text();
                setpasswordmessage(`Failed to Update Password: ${errorMessage}`);
            }
        } catch (error) {
            console.error('Fetch Error:', error);
            setpasswordmessage('An error occurred ');
        } finally {
            setnewpassword('');
        }
    };
    return (
        <div>
            <h1>Profile</h1>
            <div>
                <label>First Name</label>
                <input 
                type="text"
                value={profile.first_name}
                onChange={(e) => setprofile({ ...profile, first_name: e.target.value })} 
                disabled={!editable}/>
            </div>
            <div>
                <label>Last Name</label>
                <input 
                type="text"
                value={profile.last_name} 
                onChange={(e) => setprofile({ ...profile, last_name: e.target.value })} 
                disabled={!editable} />
            </div>
            <div>
                <label>Phone No.</label>
                <input 
                type="tel" 
                value={profile.phone} 
                onChange={(e) => setprofile({ ...profile, phone: e.target.value })} 
                disabled={!editable} />
            </div>
            <div>
                <label>Email</label>
                <input 
                type="email" 
                value={profile.email} 
                disabled />
            </div>
            {editable ? (
                <button className="save-btn" onClick={handleSave}>Save</button>
            ) : (
                <button className="edit-btn" onClick={() => seteditable(true)}>Edit</button>
            )}
            <div>
                <h3>Update Password</h3>
                <input 
                type="password" placeholder="New Password" 
                value={newpassword} 
                onChange={(e) => setnewpassword(e.target.value)} />
                <button onClick={handleUpdatePassword}>Update Password</button>
                {passwordmessage && <p>{passwordmessage}</p>}
            </div>

            <button className="add-task-btn" onClick={() => setshowtaskdialog(true)}>
                Add Task
            </button>
            {showtaskdialog && <Task onClose={() => setshowtaskdialog(false)} />}
        </div>
    );
};
export default Profile;
