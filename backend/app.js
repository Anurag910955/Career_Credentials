const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors');
const routes = require('./routes');
const app = express();
app.use(bodyParser.json()); // it is for the middleware setup 
app.use(cors({
    origin: 'http://localhost:3000', // for running frontend
    credentials: true,}));
app.use(session({
    secret: 'new secret key', 
    resave: false,
    saveUninitialized: false,
    cookie:{
        secure: false, 
        maxAge: 3600000,
    },}));
app.use('/api',routes); // setting up the router
app.listen(5000,()=>console.log('Backend running on http://localhost:5000'));
