import type { Site, Metadata, Socials } from "@types";

export const SITE: Site = {
  NAME: "Luchian Marc",
  EMAIL: "luchianmarc14@gmail.com",
  NUM_POSTS_ON_HOMEPAGE: 3,
  NUM_WORKS_ON_HOMEPAGE: 2,
  NUM_PROJECTS_ON_HOMEPAGE: 3,
};

export const HOME: Metadata = {
  TITLE: "Home",
  DESCRIPTION: "A blog where I post a part of my cybersecurity activity.",
};

export const BLOG: Metadata = {
  TITLE: "Blog",
  DESCRIPTION: "A collection of write-ups for challenges I created or I find interesting.",
};

export const WORK: Metadata = {
  TITLE: "Work",
  DESCRIPTION: "Job experience.",
};

export const CERTIFICATIONS: Metadata = {
  TITLE: "Certifications",
  DESCRIPTION: "A collection of my cyber security certifications.",
};

export const SOCIALS: Socials = [
  { 
    NAME: "linkedin",
    HREF: "https://www.linkedin.com/in/marc-luchian-0a295924a",
  }
];
