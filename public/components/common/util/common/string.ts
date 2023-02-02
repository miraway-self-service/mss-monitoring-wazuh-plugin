import { i18n } from '@osd/i18n';

export const translate = (key: string, defaultMessage: string = ' '): string => {
  return i18n.translate(key, { defaultMessage });
};

export const convertCamelCase = (words: string): string => {
  return words
    .split(' ')
    .map((word: string, index: number) => {
      if (index > 0) {
        return word.charAt(0).toUpperCase() + word.slice(1);
      }

      return word.toLowerCase();
    })
    .join(' ')
    .replace(/\s/g, '');
};
