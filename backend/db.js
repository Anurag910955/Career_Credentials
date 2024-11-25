const mysql = require('mysql2');
const dbconnection = mysql.createConnection // connecting with database
({ host: '127.0.0.1', // hostname
    user: 'root',
    password: '@Success910', 
    database: 'project_manager',
});
dbconnection.connect((err) => {
    if (err) {
        console.error('database coonection failed please resolve the issue:', err.message);
    } else {
        console.log('connection is successfull , you can proceed further');
    }
});
//exporting the connection so that it can be used in other modules
module.exports = dbconnection;

