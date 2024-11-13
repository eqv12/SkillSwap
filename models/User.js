import mongoose from "mongoose";
const { Schema } = mongoose;

const userSchema = new Schema({
  rollno: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);
export { User };
