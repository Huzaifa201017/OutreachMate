import { X } from 'lucide-react';


interface FormProps {
    closeForm: () => void;
}

const Form: React.FC<FormProps> = ({ closeForm }) => {
    return (
        <div className="content-wrapper">
            <button
                className="close-button"
                onClick={closeForm}
            >
                <X size={20} />
            </button>
            <h2>Contact Us</h2>
            <form onSubmit={(e) => e.preventDefault()}>
                <div className="form-group">
                    <input type="text" placeholder="Name" required />
                </div>
                <div className="form-group">
                    <input type="email" placeholder="Email" required />
                </div>
                <div className="form-group">
                    <textarea placeholder="Message" rows={4} required></textarea>
                </div>
                <button type="submit" className="submit-button">
                    Send Message
                </button>
            </form>
        </div>
    );
};

export default Form;
