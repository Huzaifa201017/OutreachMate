import { useState } from 'react';

interface EmailTemplate {
    id: string;
    name: string;
    content: string;
}

interface FormData {
    firstName: string;
    email: string;
    selectedTemplate: string;
}




interface CustomerFormProps {
    onPreview: (content: string) => void;
}

const emailTemplates: EmailTemplate[] = [
    {
        id: '1',
        name: 'Welcome Email',
        content: `Dear {firstName},

I hope this email finds you well. I wanted to personally welcome you to our platform.

Best regards,
Your Name`,
    },
    {
        id: '2',
        name: 'Follow-up Template',
        content: `Hi {firstName},

I'm following up on our previous conversation. I'd love to hear your thoughts.

Best,
Your Name`,
    },
    {
        id: '3',
        name: 'Meeting Request',
        content: `Dear {firstName},

I would like to schedule a meeting to discuss potential collaboration opportunities.

Looking forward to your response,
Your Name`,
    },
];

export function Form({ onPreview }: CustomerFormProps) {
    const [formData, setFormData] = useState<FormData>({
        firstName: '',
        email: '',
        selectedTemplate: '',
    });

    const handleInputChange = (
        e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>
    ) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value,
        });
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        const template = emailTemplates.find(
            (t) => t.id === formData.selectedTemplate
        );
        if (template) {
            const personalizedContent = template.content.replace(
                /{firstName}/g,
                formData.firstName
            );
            onPreview(personalizedContent);
        }
    };

    return (
        <form onSubmit={handleSubmit} className="pt-6">
            <div className="space-y-4">
                <div>
                    <label className="block text-sm font-medium text-gray-700">
                        Recipient's Name
                    </label>
                    <input
                        type="text"
                        name="firstName"
                        value={formData.firstName}
                        onChange={handleInputChange}
                        className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 bg-gray-50 p-2"
                        placeholder="Enter recipient's name"
                        required
                    />
                </div>
                <div>
                    <label className="block text-sm font-medium text-gray-700">
                        Email
                    </label>
                    <input
                        type="email"
                        name="email"
                        value={formData.email}
                        onChange={handleInputChange}
                        className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 bg-gray-50 p-2"
                        placeholder="Enter recipient's email"
                        required
                    />
                </div>
                <div>
                    <label className="block text-sm font-medium text-gray-700">
                        Email Template
                    </label>
                    <select
                        name="selectedTemplate"
                        value={formData.selectedTemplate}
                        onChange={handleInputChange}
                        className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 bg-gray-50 p-2"
                        required
                    >
                        <option value="">Select a template</option>
                        {emailTemplates.map((template) => (
                            <option key={template.id} value={template.id}>
                                {template.name}
                            </option>
                        ))}
                    </select>
                </div>
            </div>

            <button
                type="submit"
                className="w-full mt-10 bg-blue-500 text-white py-2 px-4 rounded-md hover:bg-blue-600 transition-colors duration-200 flex items-center justify-center space-x-2"
            >
                <span>Preview Email</span>
            </button>
        </form>
    );
}
