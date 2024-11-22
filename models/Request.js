import mongoose from "mongoose";
const { Schema } = mongoose;

const requestSchema = new Schema({
    senderId: { type: String, required: true, ref: 'User', index: true},
    tutorId: { type: String, ref: 'User', index: true},
    subjectId: { type: Number, ref: 'Skill', required: true, index: true },
    description: { type: String, required: true },
    status: { type: String, enum: ['Pending', 'Accepted', 'Rejected'], default: 'Pending', index: true},
    rejectedBy: [{type: Schema.Types.ObjectId, ref: 'User'}]
});

const Request = mongoose.model("Request", requestSchema);
export { Request };
