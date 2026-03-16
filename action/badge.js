/**
 * Generates a shields.io badge URL and markdown snippet for a given Trust Score.
 */

/**
 * @param {number} score - Trust Score 0-100
 * @returns {string} shields.io badge URL
 */
export function getBadgeUrl(score) {
    let color;
    if (score >= 80) color = 'brightgreen';
    else if (score >= 60) color = 'yellow';
    else if (score >= 40) color = 'orange';
    else color = 'red';

    return `https://img.shields.io/badge/Vantyr_Trust_Score-${score}%2F100-${color}`;
}

/**
 * @param {number} score - Trust Score 0-100
 * @returns {string} Markdown image tag
 */
export function getBadgeMarkdown(score) {
    const url = getBadgeUrl(score);
    return `![Vantyr Trust Score](${url})`;
}
