import express, { json, urlencoded } from 'express';
import { connect } from 'mongoose';
import {User} from './models/User.js';

const app = express();
const port = 3000;
const dbURI = 'mongodb+srv://ramya:Wimmss123.@dev-skill-swap-cluster.efbjn.mongodb.net/skillSwap?retryWrites=true&w=majority&appName=dev-skill-swap-cluster'

connect(dbURI)
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => console.error('MongoDB connection error', err));

app.use(json())
app.use(urlencoded({extended: true}));

app.post('/register', async (req, res) => {
    const { rollno, name, password } = req.body;

    try {
        const newUser = new User({ rollno, name, password })
        await newUser.save();
        res.status(201).send('User registered successfully');
    } catch(error) {
        console.error('Error registering user: ', error);
        res.status(500).send('Error registering user');
    }
})

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
})


