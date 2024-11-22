import mongoose from "mongoose";
const { Schema } = mongoose;

const userSchema = new Schema({
  rollno: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  password: { type: String, required: true },
  phone: {type: String, defaut: '123'},
  skills:[{type: Number, ref: 'Skill'}]
});

const User = mongoose.model("User", userSchema);
export { User };

