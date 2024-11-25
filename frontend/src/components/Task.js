import React, { useState } from 'react';
import './Task.css';  // importing css file for styling
// states
const Task = ({ onClose }) => {
    const [task, task_set] = useState('');
    const [start_date, set_start_date] = useState('');
    const [end_date, set_end_date] = useState('');
    // function that send post request to endserver to add new task
    const handleSubmit = async (e) => {
        e.preventDefault();
        const respose = await fetch('http://localhost:5000/api/tasks', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
                task,
                start_date: start_date,
                end_date: end_date,}),
        });
        // if the respose is ok.
        if (respose.ok) {
            alert('Task added successfully!');
            onClose();
        } else {
            alert('Failed to add task');
        }
    };
    return (
        <div id='main' >
            <h2>Add New Task</h2>
            <form onSubmit={handleSubmit}>
                <label>Task Name</label>
                <input 
                type="text" placeholder="Enter task" 
                value={task} 
                onChange={(e) => task_set(e.target.value)} 
                required />
                <label>Start Date</label>
                <input type="date" 
                value={start_date} 
                onChange={(e) => set_start_date(e.target.value)} 
                required  />
                <label>End Date</label>
                <input type="date" 
                value={end_date} 
                onChange={(e) => set_end_date(e.target.value)} 
                required />
                <button type="submit">Add Task</button>
                <button type="button" onClick={onClose}>Cancel</button>
            </form>
        </div>
    );
};
export default Task;