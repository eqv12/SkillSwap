import mongoose from "mongoose";
import AutoIncrementFactory from "mongoose-sequence";
const { Schema } = mongoose;


//const AutoIncrement = AutoIncrementFactory(mongoose);
const skillsSchema = new Schema({
    _id: {type: Number},
    skill: { type: String, required: true, unique: true },
});

// skillsSchema.plugin(AutoIncrement, { id: 'skills', inc_field: '_id' });
const Skill = mongoose.model("Skill", skillsSchema);
export { Skill };
