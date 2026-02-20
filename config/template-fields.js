/**
 * TEMPLATE_STRUCTURE — maps each template to its required/optional fields.
 * Used by the AI Interview mode to dynamically generate questions.
 */

const COMMON_REQUIRED = [
  { key: "fullName",   label: "Full Name",            type: "text",       question: "What is your full name?" },
  { key: "roleTitle",  label: "Job Title",             type: "text",       question: "What is your current or desired job title?" },
  { key: "phone",      label: "Phone Number",          type: "text",       question: "What is your phone number?" },
  { key: "email",      label: "Email Address",          type: "text",       question: "What is your email address?" },
  { key: "location",   label: "Location",              type: "text",       question: "What is your city and state/country?" },
  { key: "summary",    label: "Professional Summary",   type: "textarea",   question: null },
  { key: "experience", label: "Experience",             type: "experience", question: "Tell me about your work experience. Include job title, company, dates, and key responsibilities (you can describe multiple roles)." },
  { key: "education",  label: "Education",              type: "textarea",   question: "Tell me about your education (degree, institution, year)." },
  { key: "skills",     label: "Skills",                type: "skills",     question: "List your key skills, separated by commas or new lines." },
  { key: "languages",  label: "Languages",             type: "textarea",   question: "What languages do you speak, and at what level?" },
];

const PHOTO_OPTIONAL = { key: "profileImageUrl", label: "Profile Photo URL", type: "url" };

const PHOTO_TEMPLATES = ["modern-1", "bold-sidebar", "creative-gradient"];

export const TEMPLATE_STRUCTURE = {
  "modern-1":          { required: [...COMMON_REQUIRED], optional: [PHOTO_OPTIONAL] },
  "bold-sidebar":      { required: [...COMMON_REQUIRED], optional: [PHOTO_OPTIONAL] },
  "minimal-1":         { required: [...COMMON_REQUIRED], optional: [] },
  "creative-gradient": { required: [...COMMON_REQUIRED], optional: [PHOTO_OPTIONAL] },
  "corporate-clean":   { required: [...COMMON_REQUIRED], optional: [] },
  "elegant-serif":     { required: [...COMMON_REQUIRED], optional: [] },
  "tech-focused":      { required: [...COMMON_REQUIRED], optional: [] },
  "classic-border":    { required: [...COMMON_REQUIRED], optional: [] },
};

export function getFieldsForTemplate(id) {
  const entry = TEMPLATE_STRUCTURE[id] || TEMPLATE_STRUCTURE["modern-1"];
  return [...entry.required, ...entry.optional];
}

export function isPhotoTemplate(id) {
  return PHOTO_TEMPLATES.includes(id);
}
