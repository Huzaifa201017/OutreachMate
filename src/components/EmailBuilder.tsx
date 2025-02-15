import React, { useState, useEffect, useRef } from 'react';
import {
    Send,
    User,
    AtSign,
    Tag,
    Eye,
    Paperclip,
    Upload,
    X,
} from 'lucide-react';

// Sample preset attachments
const presetAttachments = [
    {
        id: 1,
        name: 'Company Overview.pdf',
        size: '2.4 MB',
        type: 'application/pdf',
    },
    {
        id: 2,
        name: 'Product Brochure.pdf',
        size: '3.1 MB',
        type: 'application/pdf',
    },
    {
        id: 3,
        name: 'Case Study - Success Story.pdf',
        size: '1.8 MB',
        type: 'application/pdf',
    },
    {
        id: 4,
        name: 'Technical Specifications.pdf',
        size: '1.2 MB',
        type: 'application/pdf',
    },
    {
        id: 5,
        name: 'Price List 2024.pdf',
        size: '890 KB',
        type: 'application/pdf',
    },
];

const emailTemplates = [
    {
        id: 1,
        category: 'Lead',
        name: 'Product Introduction',
        subject: 'Revolutionize Your {Industry} with {ProductName}',
        content: `Hi {FirstName},

I noticed that {CompanyName} has been making waves in the {Industry} space, and I thought you might be interested in how {ProductName} could help streamline your operations.

Would you be open to a quick 15-minute chat this week to discuss how we can help {CompanyName} achieve {Goal}?

Best regards,
{SenderName}`,
    },
    {
        id: 2,
        category: 'Lead',
        name: 'Follow-up Meeting Request',
        subject: 'Quick Follow-up: {ProductName} for {CompanyName}',
        content: `Hi {FirstName},

I wanted to follow up on my previous email about how {ProductName} could benefit {CompanyName}'s {Industry} operations.

I'd love to show you a quick demo of how we've helped similar companies achieve {Goal}. Would you have 15 minutes this week for a brief call?

Best regards,
{SenderName}`,
    },
    {
        id: 3,
        category: 'Recruiter',
        name: 'Job Application',
        subject: 'Experienced {Role} Looking to Join {CompanyName}',
        content: `Dear {FirstName},

I hope this email finds you well. I came across the {Role} position at {CompanyName} and was immediately excited about the opportunity.

With {Experience} years of experience in {Industry}, I believe I could bring valuable insights to your team.

Would you be available for a brief call to discuss how my background aligns with {CompanyName}'s needs?

Best regards,
{SenderName}`,
    },
    {
        id: 4,
        category: 'Recruiter',
        name: 'Referral Follow-up',
        subject: 'Referred by {ReferralName} for {Role} Position',
        content: `Dear {FirstName},

{ReferralName} suggested I reach out to you regarding the {Role} position at {CompanyName}. 

I've been working in {Industry} for {Experience} years, and I'm particularly impressed with {CompanyName}'s work on {ProjectName}.

I'd love to discuss how my experience aligns with your team's needs. Would you be available for a brief conversation this week?

Best regards,
{SenderName}`,
    },
    {
        id: 5,
        category: 'Investor',
        name: 'Pitch Deck Introduction',
        subject: 'Investment Opportunity: {CompanyName} - {Industry} Innovation',
        content: `Dear {FirstName},

I'm reaching out regarding an investment opportunity in {CompanyName}, an innovative startup in the {Industry} space.

We've achieved {Milestone} and are currently raising {Amount} to scale our operations. Our current metrics show {Growth} growth month-over-month.

Would you be interested in reviewing our pitch deck? I'd be happy to schedule a call to discuss the opportunity in detail.

Best regards,
{SenderName}`,
    },
    {
        id: 6,
        category: 'Business Partner',
        name: 'Partnership Proposal',
        subject: 'Potential Partnership Between {CompanyName} and {PartnerCompany}',
        content: `Dear {FirstName},

I'm reaching out because I see great potential for collaboration between {CompanyName} and {PartnerCompany} in the {Industry} space.

Our {Product} would complement your {PartnerProduct}, creating a comprehensive solution for {Target} customers.

Would you be open to a discussion about how we could create mutual value through a strategic partnership?

Best regards,
{SenderName}`,
    },
];

interface Attachment {
    id: number;
    name: string;
    size: string;
    type: string;
    file?: File;
}

interface Variable {
    name: string;
    value: string;
    isEditing: boolean;
}

export default function EmailBuilder() {
    const [recipientData, setRecipientData] = useState({
        firstName: '',
        email: '',
        company: '',
        industry: '',
        category: 'Lead',
    });

    const [variables, setVariables] = useState<Record<string, Variable>>({});
    const [editedSubject, setEditedSubject] = useState('');
    const [editedContent, setEditedContent] = useState('');
    const [selectedAttachments, setSelectedAttachments] = useState<Attachment[]>(
        []
    );
    const [attachmentType, setAttachmentType] = useState<'preset' | 'upload'>(
        'preset'
    );
    // const [activeVariable, setActiveVariable] = useState<string | null>(null);
    // const variableInputRef = useRef<HTMLInputElement>(null);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const textareaRef = useRef<HTMLTextAreaElement | null>(null);

    // Filter templates based on selected category
    const filteredTemplates = emailTemplates.filter(
        (template) => template.category === recipientData.category
    );

    // Set initial template based on category
    const [selectedTemplate, setSelectedTemplate] = useState(
        filteredTemplates[0]
    );

    const adjustHeight = () => {
        if (textareaRef.current) {
            textareaRef.current.style.height = 'auto'; // Reset height
            textareaRef.current.style.height = `${textareaRef.current.scrollHeight}px`; // Set new height
        }
    };

    useEffect(() => {
        if (textareaRef.current) {
            adjustHeight(); // Adjust height on mount
        }
    }, []); // Runs once on mount

    // Extract variables from template and initialize them
    useEffect(() => {
        if (selectedTemplate) {
            const extractedVariables = new Set<string>();
            const regex = /{([^}]+)}/g;
            let match;

            // Extract from subject
            while ((match = regex.exec(selectedTemplate.subject)) !== null) {
                extractedVariables.add(match[1]);
            }

            // Extract from content
            regex.lastIndex = 0;
            while ((match = regex.exec(selectedTemplate.content)) !== null) {
                extractedVariables.add(match[1]);
            }

            // Initialize variables state
            const newVariables: Record<string, Variable> = {};
            extractedVariables.forEach((name) => {
                newVariables[name] = {
                    name,
                    value: variables[name]?.value || '',
                    isEditing: false,
                };
            });

            setVariables(newVariables);
            setEditedSubject(selectedTemplate.subject);
            setEditedContent(selectedTemplate.content);
        }
    }, [selectedTemplate]);

    const handleCategoryChange = (category: string) => {
        setRecipientData((prev) => ({ ...prev, category }));
        const templatesForCategory = emailTemplates.filter(
            (t) => t.category === category
        );
        setSelectedTemplate(templatesForCategory[0]);
    };

    const handleInputChange = (field: string, value: string) => {
        setRecipientData((prev) => ({ ...prev, [field]: value }));
    };

    //   const handleVariableClick = (variableName: string) => {
    //     if (!isEditing) {
    //       setVariables((prev) => ({
    //         ...prev,
    //         [variableName]: {
    //           ...prev[variableName],
    //           isEditing: true,
    //         },
    //       }));
    //       setActiveVariable(variableName);
    //     }
    //   };

    //   const handleVariableChange = (variableName: string, value: string) => {
    //     setVariables((prev) => ({
    //       ...prev,
    //       [variableName]: {
    //         ...prev[variableName],
    //         value,
    //       },
    //     }));
    //   };

    //   const handleVariableBlur = (variableName: string) => {
    //     setVariables((prev) => ({
    //       ...prev,
    //       [variableName]: {
    //         ...prev[variableName],
    //         isEditing: false,
    //       },
    //     }));
    //     setActiveVariable(null);
    //   };

    //   const renderVariableContent = (text: string) => {
    //     const regex = /{([^}]+)}/g;
    //     const parts = [];
    //     let lastIndex = 0;
    //     let match;

    //     while ((match = regex.exec(text)) !== null) {
    //       const [fullMatch, variableName] = match;
    //       const variable = variables[variableName];

    //       // Add text before the variable
    //       if (match.index > lastIndex) {
    //         parts.push(text.substring(lastIndex, match.index));
    //       }

    //       // Add the variable
    //       if (variable) {
    //         if (isEditing) {
    //           parts.push(fullMatch);
    //         } else if (variable.isEditing && activeVariable === variableName) {
    //           parts.push(
    //             <input
    //               key={`input-${variableName}`}
    //               ref={variableInputRef}
    //               type="text"
    //               value={variable.value}
    //               onChange={(e) =>
    //                 handleVariableChange(variableName, e.target.value)
    //               }
    //               onBlur={() => handleVariableBlur(variableName)}
    //               className="inline-block px-2 py-1 border rounded bg-blue-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
    //               autoFocus
    //             />
    //           );
    //         } else {
    //           parts.push(
    //             <span
    //               key={`var-${variableName}`}
    //               onClick={() => handleVariableClick(variableName)}
    //               className="inline-block px-2 py-1 bg-blue-100 rounded cursor-pointer hover:bg-blue-200"
    //             >
    //               {variable.value || `{${variableName}}`}
    //             </span>
    //           );
    //         }
    //       }

    //       lastIndex = match.index + fullMatch.length;
    //     }

    //     // Add remaining text
    //     if (lastIndex < text.length) {
    //       parts.push(text.substring(lastIndex));
    //     }

    //     return parts;
    //   };

    const handlePresetAttachment = (attachment: Attachment) => {
        if (selectedAttachments.find((a) => a.id === attachment.id)) {
            setSelectedAttachments((prev) =>
                prev.filter((a) => a.id !== attachment.id)
            );
        } else {
            setSelectedAttachments((prev) => [...prev, attachment]);
        }
    };

    const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
        const files = event.target.files;
        if (files) {
            Array.from(files).forEach((file) => {
                const newAttachment: Attachment = {
                    id: Date.now() + Math.random(),
                    name: file.name,
                    size: `${(file.size / (1024 * 1024)).toFixed(2)} MB`,
                    type: file.type,
                    file,
                };
                setSelectedAttachments((prev) => [...prev, newAttachment]);
            });
        }
        if (fileInputRef.current) {
            fileInputRef.current.value = '';
        }
    };

    const removeAttachment = (id: number) => {
        setSelectedAttachments((prev) => prev.filter((a) => a.id !== id));
    };

    return (
        <div className="flex-1 flex overflow-hidden">
            {/* Left Panel - Input Fields */}
            <div className="w-1/2 p-6 overflow-y-auto border-r">
                <div className="space-y-6">
                    {/* Recipient Details */}
                    <div className="space-y-4">
                        <h3 className="text-lg font-semibold text-gray-900">
                            Recipient Details
                        </h3>
                        <div className="space-y-3">
                            <div className="flex items-center space-x-2">
                                <User className="w-5 h-5 text-gray-400" />
                                <input
                                    type="text"
                                    placeholder="Recipient Name"
                                    value={recipientData.firstName}
                                    onChange={(e) =>
                                        handleInputChange('firstName', e.target.value)
                                    }
                                    className="flex-1 p-2 border rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                />
                            </div>
                            <div className="flex items-center space-x-2">
                                <AtSign className="w-5 h-5 text-gray-400" />
                                <input
                                    type="email"
                                    placeholder="Email Address"
                                    value={recipientData.email}
                                    onChange={(e) => handleInputChange('email', e.target.value)}
                                    className="flex-1 p-2 border rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                />
                            </div>
                            <div className="flex items-center space-x-2">
                                <Tag className="w-5 h-5 text-gray-400" />
                                <select
                                    value={recipientData.category}
                                    onChange={(e) => handleCategoryChange(e.target.value)}
                                    className="flex-1 p-2 border rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                >
                                    <option value="Lead">Lead</option>
                                    <option value="Recruiter">Recruiter</option>
                                    <option value="Investor">Investor</option>
                                    <option value="Business Partner">Business Partner</option>
                                </select>
                            </div>
                        </div>
                    </div>

                    {/* Template Selection */}
                    <div className="space-y-4">
                        <h3 className="text-lg font-semibold text-gray-900">
                            Email Template
                        </h3>
                        <select
                            value={selectedTemplate?.id}
                            onChange={(e) => {
                                const template = filteredTemplates.find(
                                    (t) => t.id === parseInt(e.target.value)
                                );
                                if (template) setSelectedTemplate(template);
                            }}
                            className="w-full p-2 border rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        >
                            {filteredTemplates.map((template) => (
                                <option key={template.id} value={template.id}>
                                    {template.name}
                                </option>
                            ))}
                        </select>
                    </div>

                    {/* Attachments Section */}
                    <div className="space-y-4">
                        <h3 className="text-lg font-semibold text-gray-900">Attachments</h3>
                        <div className="space-y-4">
                            <div className="flex space-x-4">
                                <button
                                    onClick={() => setAttachmentType('preset')}
                                    className={`flex-1 py-2 px-4 rounded-md ${attachmentType === 'preset'
                                        ? 'bg-blue-600 text-white'
                                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                                        }`}
                                >
                                    <Paperclip className="w-4 h-4 inline-block mr-2" />
                                    Choose from list
                                </button>
                                <button
                                    onClick={() => setAttachmentType('upload')}
                                    className={`flex-1 py-2 px-4 rounded-md ${attachmentType === 'upload'
                                        ? 'bg-blue-600 text-white'
                                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                                        }`}
                                >
                                    <Upload className="w-4 h-4 inline-block mr-2" />
                                    Upload files
                                </button>
                            </div>

                            {attachmentType === 'preset' ? (
                                <div className="space-y-2">
                                    {presetAttachments.map((attachment) => (
                                        <div
                                            key={attachment.id}
                                            className={`flex items-center justify-between p-3 rounded-md border cursor-pointer transition-colors ${selectedAttachments.find((a) => a.id === attachment.id)
                                                ? 'border-blue-500 bg-blue-50'
                                                : 'border-gray-200 hover:border-blue-300'
                                                }`}
                                            onClick={() => handlePresetAttachment(attachment)}
                                        >
                                            <div className="flex items-center space-x-3">
                                                <Paperclip className="w-4 h-4 text-gray-400" />
                                                <span className="text-sm font-medium">
                                                    {attachment.name}
                                                </span>
                                            </div>
                                            <span className="text-sm text-gray-500">
                                                {attachment.size}
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="space-y-4">
                                    <div
                                        className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center cursor-pointer hover:border-blue-500 transition-colors"
                                        onClick={() => fileInputRef.current?.click()}
                                    >
                                        <Upload className="w-8 h-8 mx-auto text-gray-400 mb-2" />
                                        <p className="text-sm text-gray-600">
                                            Click to upload or drag and drop files here
                                        </p>
                                    </div>
                                    <input
                                        type="file"
                                        ref={fileInputRef}
                                        className="hidden"
                                        multiple
                                        onChange={handleFileUpload}
                                    />
                                </div>
                            )}

                            {selectedAttachments.length > 0 && (
                                <div className="mt-4">
                                    <h4 className="text-sm font-medium text-gray-700 mb-2">
                                        Selected Attachments
                                    </h4>
                                    <div className="space-y-2">
                                        {selectedAttachments.map((attachment) => (
                                            <div
                                                key={attachment.id}
                                                className="flex items-center justify-between p-2 bg-gray-50 rounded-md"
                                            >
                                                <div className="flex items-center space-x-2">
                                                    <Paperclip className="w-4 h-4 text-gray-400" />
                                                    <span className="text-sm">{attachment.name}</span>
                                                </div>
                                                <button
                                                    onClick={() => removeAttachment(attachment.id)}
                                                    className="text-red-500 hover:text-red-700"
                                                >
                                                    <X className="w-4 h-4" />
                                                </button>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            {/* Right Panel - Preview */}
            <div className="w-1/2 p-6 bg-gray-50 overflow-y-scroll">
                <div className="bg-white rounded-lg shadow p-6 space-y-4">
                    <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                            <Eye className="w-5 h-5" /> Preview
                        </h3>
                        <button className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700">
                            <Send className="w-4 h-4 inline-block mr-1" /> Send Email
                        </button>
                    </div>

                    <div className="space-y-4">
                        <div className="border-b pb-4">
                            <h4 className="text-sm font-medium text-gray-500">Subject</h4>
                            <input
                                type="text"
                                value={editedSubject}
                                onChange={(e) => setEditedSubject(e.target.value)}
                                className="w-full mt-1 bg-transparent border-none outline-none"
                            />
                        </div>
                        <div>
                            <h4 className="text-sm font-medium text-gray-500 mb-2">
                                Content
                            </h4>

                            <textarea
                                value={editedContent}
                                ref={textareaRef}
                                onChange={(e) => {
                                    setEditedContent(e.target.value);
                                    adjustHeight(); // Adjust height dynamically
                                }}
                                className="w-full mb-4 bg-transparent border-none outline-none resize-none overflow-hidden leading-relaxed"
                                style={{ minHeight: '40px', height: 'auto' }} // Ensures it's not collapsed initially
                            />
                        </div>

                        {selectedAttachments.length > 0 && (
                            <div className="border-t pt-4">
                                <h4 className="text-sm font-medium text-gray-500 mb-2">
                                    Attachments
                                </h4>
                                <div className="space-y-2">
                                    {selectedAttachments.map((attachment) => (
                                        <div
                                            key={attachment.id}
                                            className="flex items-center space-x-2 text-sm text-gray-600"
                                        >
                                            <Paperclip className="w-4 h-4" />
                                            <span>{attachment.name}</span>
                                            <span className="text-gray-400">({attachment.size})</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
