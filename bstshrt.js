//bypass bstshrt
const axios = require('axios');
const cherrio = require('cheerio');

class Bstshrt {
    constructor(headers,method,credentials) { this.headers = {
        headers: {
            'accept': '*/*',
            'accept-language': 'en,vi-VN;q=0.9,vi;q=0.8,fr-FR;q=0.7,fr;q=0.6,en-US;q=0.5',
            'content-length': '0',
            'origin': 'https://bstshrt.com',
            'priority': 'u=1, i',
            'sec-ch-ua': '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
            }
        },this.method = {
            method: 'GET',
        },this.credentials = {
            credentials: 'include',
        };
    
    }

    }

    const url = "https://bstshrt.com/u/izsjou";

    async function check_text() {
        const response = await axios.get(url);
        const $ = cherrio.load(response.data);
        const text = $('body').text();
        const regex = /"finalUrl\\*"\s*:\s*\\*"(https?:\/\/[^\\"]+)/
                const match = text.match(regex);
        console.log(match[1]);
    }
    check_text();
