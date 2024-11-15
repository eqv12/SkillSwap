import express, { json, urlencoded } from "express";
import { connect } from "mongoose";
import { User } from "./models/User.js";
import cors from "cors";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;
const dbURI =
  "mongodb+srv://ramya:Wimmss123.@dev-skill-swap-cluster.efbjn.mongodb.net/skillSwap?retryWrites=true&w=majority&appName=dev-skill-swap-cluster";

connect(dbURI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error", err));

app.use(express.static("public"));

app.use(cors());
app.use(json());
app.use(urlencoded({ extended: true }));

// app.get("/login", (req, res) => {
//   res.sendFile(path.join(__dirname, "public", "login.html"));
// });

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
})

app.get("/register", (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'))
})

app.post("/register", async (req, res) => {
  const { rollno, name, password } = req.body;
  console.log(rollno, name, password);

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ rollno: rollno, name: name, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully", status: 201 });
  } catch (error) {
    console.error("Error registering user: ", error);
    res.status(500).json({ message: "Error registering user", status: 500 });
  }
});

app.post("/login", async (req, res) => {
  console.log(req.body);
  const { rollno, password } = req.body;
  try {
    const user = await User.findOne({ rollno: rollno });

    if (user && (await bcrypt.compare(password, user.password))) {
      res.status(200).json({ message: "User credentials authenticated", status: 200 });
    } else {
      res.status(401).json({ message: "Bad credentials", status: 401 });
    }
  } catch (error) {
    console.error("Error during login: ", error);
    res.status(500).send("Error logging in");
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
