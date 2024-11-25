const express=require('express');
const bcrypt=require('bcrypt'); // importing bcrypt for hashing 
const dbconnection= require('./db'); // importing database connection
const router = express.Router();
// user login route with hashed password comparision
router.post('/login', (request, response) => {
    const { username, password } = request.body;
    dbconnection.query('SELECT * FROM members WHERE username = ? OR email = ?', [username, username], async (err, results) => {
        if (err || results.length === 0) {
            return response.status(401).send('Invalid username or email');
        }
        const user = results[0];
        try {
            const match = await bcrypt.compare(password, user.password); // compares hashed password with user typed password
            if (match) {
                request.session.user = { id: user.id, username: user.username }; // for storing session data
                response.send('Login successful');
            } else {
                res.status(401).send('invalid password ');
            }
        } catch (err) {
            console.error(err);
            response.status(500).send('eror ! cannot verify');
        }
    });
});
// view profile route
router.get('/profile', (request, response) => {
    if (!request.session.user) return response.status(403).send('user is not logged in.');
    dbconnection.query(
        'SELECT first_name, last_name, phone, email FROM members WHERE id = ?',
        [request.session.user.id],
        (err, results) => {
            if (err) return response.status(500).send('eror in fetching profile . please try again later');
            response.json(results[0]);
        }
    );
});
// route for updating user profile
router.put('/profile', (request, response) => {
    const { first_name, last_name, phone, email } = request.body;
    dbconnection.query(
        'UPDATE members SET first_name = ?, last_name = ?, phone = ?, email = ? WHERE id = ?',
        [first_name, last_name, phone, email, request.session.user.id],
        (err) => {
            if (err) return response.status(500).send('eror in updating profile');
            response.send('congrats profile updated successfully.');
        }
    );
});
// route for updating user password
router.put('/profile/password', async (request, response) => {
    const { new_password } = request.body;
    try {
        const hashedPassword = await bcrypt.hash(new_password, 10); // convert the new password's hash
        dbconnection.query(
            'UPDATE members SET password = ? WHERE id = ?',
            [hashedPassword, request.session.user.id],
            (err) => {
                if (err) {
                    console.error('Database Error:', err);
                    return response.status(500).send('eror in updating password');
                }
                response.send('password has been updated!');
            }
        );
    } catch (err) {
        console.error('Error hashing password:', err);
        response.status(500).send('eror in processing password.');
    }
});
// route for adding task 
router.post('/tasks', (request, response) => {
    const { task, start_date, end_date } = request.body;
    dbconnection.query(
        'INSERT INTO activities (member_id, task, start_date, end_date) VALUES (?, ?, ?, ?)',
        [request.session.user.id, task, start_date, end_date],
        (err) => {
            if (err) return response.status(500).send('not able to add task');
            response.send('congrats task added successfully');
        }
    );
});
module.exports = router;
