const express = require('express');
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcrypt');
const session = require('express-session')
const UserSchema = require('./UserSchema');
const TodoSchema = require('./TodoSchema');
const mongoDbSession = require('connect-mongodb-session')(session)
const app = express();

const mongoURI = `mongodb+srv://Prudhvi876:Prudhvi876@cluster0.xa0edpx.mongodb.net/backend?retryWrites=true&w=majority`

const store = new mongoDbSession({
    uri : mongoURI,
    collection : 'sessions'
})
app.use(express.json());
app.use(express.urlencoded({extended: true}));




app.use(session({
    secret: 'hello backendjs',
    resave: false,
    saveUninitialized: false,
    store: store
}))



mongoose.connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(res => {
    console.log('Connected to db successfully');
}).catch(err => {
    console.log('Failed to connect', err);
})

app.get('/', (req, res) => {
    res.send('Welcome to our app');
})

app.get('/login',(req,res)=>{
    res.send({
        status :200,
        message : "Login Successful"
    })
})

app.get('/register',(req,res)=>{
    res.send({
        status :200,
        message : "Register Successful"
    })
})

app.get("/profile",(req,res)=>{
    if(!req.session.isAuth){
        return res.send("Invalid session. Please Log in")
    }

    res.send("Welcome to the app")
})

function cleanUpAndValidate({name, username, phone, email, password}) {
    return new Promise((resolve, reject) => {

        if(typeof(email) !== 'string')  
            reject('Invalid Email');
        if(typeof(username) !== 'string')  
            reject('Invalid Username');
        if(typeof(name) !== 'string')  
            reject('Invalid name');
        if(typeof(password) !== 'string')
            reject('Invalid Password');

        // Empty strings evaluate to false
        if(!username || !password || !name || !email)
            reject('Invalid Data');

        if(username.length < 3 || username.length > 100) 
            reject('Username should be 3 to 100 charcters in length');
        
        if(password.length < 5 || password > 300)
            reject('Password should be 5 to 300 charcters in length');

        if(!validator.isEmail(email)) 
            reject('Invalid Email');

        if(phone !== undefined && typeof(phone) !== 'string') 
            reject('Invalid Phone');
        
        if(phone !== undefined && typeof(phone) === 'string') {
            if(phone.length !== 10 && validator.isAlphaNumeric(phone)) 
                reject('Invalid Phone');
        }

        resolve();
    })
}

app.post('/register', async (req, res) => {
    const { name, username, password, phone, email } = req.body;

    // Validation of Data
    try {
        await cleanUpAndValidate({name, username, password, phone, email});
    }
    catch(err) {
        return res.send({
            status: 400, 
            message: err
        })
    }

    let userExists;
    // Check if user already exists
    try {
        userExists = await UserSchema.findOne({email});
    }
    catch(err) {
        return res.send({
            status: 400,
            message: "Internal Server Error. Please try again.",
            error: err  
        })
    }

    if(userExists) 
        return res.send({
            status: 400,
            message: "User with email already exists"
        })

    try {
        userExists = await UserSchema.findOne({username});
    }
    catch(err) {
        return res.send({
            status: 400,
            message: "Internal Server Error. Please try again.",
            error: err  
        })
    }

    if(userExists) 
        return res.send({
            status: 400,
            message: "Username already taken"
        })

    // Hash the password Plain text -> hash 
    const hashedPassword = await bcrypt.hash(password, 13); // md5
    
    let user = new UserSchema({
        name,
        username,
        password: hashedPassword,
        email,
        phone
    })

    try {
        const userDb = await user.save(); // Create Operation
        return res.send({
            status: 200,
            message: "Registration Successful",
            data: {
                _id: userDb._id,
                username: userDb.username,
                email: userDb.email
            }
        });
    }
    catch(err) {
        return res.send({
            status: 400,
            message: "Internal Server Error. Please try again.",
            error: err  
        })
    }
})

app.post('/login', async (req, res) => {

    // loginId can be either email or username
    const { loginId, password } = req.body;

    if(typeof(loginId) !== 'string' || typeof(password) !== 'string' || !loginId || !password) {
        return res.send({
            status: 400,
            message: "Invalid Data"
        })
    }

    let userDb;
    try {
        if(validator.isEmail(loginId)) {
            userDb = await UserSchema.findOne({email: loginId}); 
        }
        else {
            userDb = await UserSchema.findOne({username: loginId});
        }
    }
    catch(err) {
        return res.send({
            status: 400,
            message: "Internal server error. Please try again",
            error: err
        })
    }
    

    if(!userDb) {
        return res.send({
            status: 400,
            message: "User not found",
            data: req.body
        });
    }

    // Comparing the password
    const isMatch = await bcrypt.compare(password, userDb.password);

    if(!isMatch) {
        return res.send({
            status: 400,
            message: "Invalid Password",
            data: req.body
        });
    }

    req.session.isAuth = true
    req.session.user = {username:userDb.username,email : userDb.email}

    res.send({
        status: 200,
        message: "Logged in successfully"
    });
})

app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if(err) throw err;

        res.send('Logged out successfully');
    })
})

app.listen(3000, () => {
    console.log('Listening on port 3000');
})