import { useState } from 'react';
import { Mail } from 'lucide-react';
import Form from './Form'

export default function ContentPage() {
    const [isOpen, setIsOpen] = useState(false);

    return (
        <div className={`floating-container ${isOpen ? 'form-open' : ''}`}>

            <Form closeForm={() => setIsOpen(false)} />

            <button
                className="trigger-button"
                onClick={() => setIsOpen(true)}
            >
                <Mail size={24} />
                <span>Send Mail</span>
            </button>
        </div>
    );
}