import axios from 'axios';

// ── Per-user in-memory state ──────────────────────────────────────────────────
const userQueues  = new Map(); // userId → string[]
const userPollers = new Map(); // userId → { intervalId, liveChatId, processedIds: Set, pageToken: string|null, token: string }
const cooldowns   = new Map(); // userId → Map(viewerName → lastTriggeredMs)

// ── Poll state ────────────────────────────────────────────────────────────────
const pollState = new Map(); // userId → { question, options, votes, voters(Map), active, answer }

export function startPoll(userId, question, options, answer) {
  pollState.set(userId, {
    question,
    options,
    answer,            // 'A' | 'B' | 'C' | 'D' — correct answer, kept secret until reveal
    votes:  new Array(options.length).fill(0),
    voters: new Map(), // channelId → { name, idx } — tracks who voted + what they chose
    active: true,
  });
}

export function endPoll(userId) {
  const p = pollState.get(userId);
  if (p) p.active = false;
}

export function castVote(userId, authorId, authorName, letterIdx) {
  const p = pollState.get(userId);
  if (!p || !p.active) return false;
  if (p.voters.has(authorId)) return false;
  p.voters.set(authorId, { name: authorName, idx: letterIdx });
  p.votes[letterIdx]++;
  return true;
}

export function getPoll(userId) {
  return pollState.get(userId) || null;
}

// ── Get names of viewers who voted correctly (for post-reveal shoutout) ────────
export function getCorrectVoterNames(userId, maxCount = 5) {
  const p = pollState.get(userId);
  if (!p || !p.answer) return [];
  const correctIdx = ['A','B','C','D'].indexOf(p.answer);
  const names = [];
  for (const [, { name, idx }] of p.voters) {
    if (idx === correctIdx) names.push(name);
    if (names.length >= maxCount) break;
  }
  return names;
}

const MAX_QUEUE     = 20;
const COOLDOWN_MS   = 60_000; // 1 min per viewer per user
const POLL_INTERVAL = 8_000;  // 8s

// ── Name validation ───────────────────────────────────────────────────────────
function sanitizeName(raw) {
  return String(raw || '').trim().replace(/[<>&"']/g, '').substring(0, 50);
}
function isValidName(name) {
  return name.length >= 1 && /^[\w\s\-'.]+$/u.test(name);
}

// ── Queue helpers ─────────────────────────────────────────────────────────────
export function addToQueue(userId, rawName, source = 'manual') {
  const name = sanitizeName(rawName);
  if (!isValidName(name)) return { ok: false, reason: 'Invalid name' };

  if (!userQueues.has(userId)) userQueues.set(userId, []);
  const q = userQueues.get(userId);

  if (q.length >= MAX_QUEUE)           return { ok: false, reason: 'Queue full' };
  if (q.includes(name))                return { ok: false, reason: 'Name already in queue' };

  q.push(name);
  return { ok: true, name, source };
}

export function getQueue(userId) {
  return [...(userQueues.get(userId) || [])];
}

export function shiftQueue(userId) {
  const q = userQueues.get(userId);
  if (!q || q.length === 0) return null;
  return q.shift();
}

export function clearQueue(userId) {
  userQueues.set(userId, []);
}

// ── Poller state ──────────────────────────────────────────────────────────────
export function isPollerRunning(userId) {
  return userPollers.has(userId);
}

// ── Built-in name pool (~500 names — used when name bank is empty or not uploaded) ──
const BUILTIN_NAMES = [
  // A
  'Aarav Shah','Aditya Kumar','Akash Verma','Amit Sharma','Ananya Singh',
  'Arjun Mehta','Aryan Gupta','Ayesha Khan','Abhishek Tomar','Aishwarya Roy',
  'Alok Pandey','Amrita Nair','Anand Kulkarni','Ankita Dubey','Ankit Rawat',
  'Anshul Kapur','Aparna Rao','Ashish Soni','Astha Verma','Avni Sharma',
  'Ayaan Khan','Aditi Malhotra','Arun Pillai','Archana Rao','Ajay Bhatt',
  'Akanksha Tiwari','Akhil Reddy','Alka Srivastava','Amol Desai','Amish Patel',
  'Aniket Joshi','Anisha Menon','Anjali Gupta','Anil Saxena','Animesh Dube',
  'Anju Chauhan','Ankur Singh','Anmol Khatri','Anshika Rathi','Antara Bose',
  'Anurag Wagle','Anushka Mirza','Arpit Bansal','Archit Dixit','Aruna Chandra',
  'Arvind Hegde','Ashutosh Naidu','Ashwini Oberoi','Asif Solanki','Avantika Ahmed',
  // B
  'Bhavya Patel','Babita Yadav','Baljit Singh','Brij Trivedi','Bharat Dube',
  'Bhumi Kulkarni','Bipin Goel','Bindu Bansal','Bobby Chauhan','Budh Singh',
  // C
  'Chirag Joshi','Chandan Mishra','Chandni Gupta','Chitra Pillai','Chhavi Sharma',
  'Chetan Mehta','Chanchal Rao','Chintan Patel','Charmi Nair','Charu Reddy',
  // D
  'Deepak Yadav','Devika Nair','Divya Reddy','Daksh Mehta','Disha Patel',
  'Dhruv Arora','Dimple Sinha','Dinesh Bhatt','Dolly Tiwari','Dhara Verma',
  'Deepti Saxena','Deven Kulkarni','Dhruva Jain','Diksha Pillai','Dilip Chauhan',
  // E
  'Ekta Joshi','Esha Malhotra','Elina Menon','Eklavya Rao','Eram Ansari',
  // F
  'Farhan Ansari','Faiz Khan','Farida Mirza','Faisal Sheikh','Fatima Siddiqui',
  // G
  'Gaurav Tiwari','Garima Srivastava','Gaurangi Desai','Girish Rathi','Gita Bose',
  'Gourav Wagle','Gunjan Patil','Geetanjali Ghosh','Girija Dixit','Gajendra Mathur',
  // H
  'Ishaan Malhotra','Harsh Bhatnagar','Harshita Bansal','Hemant Chauhan','Himani Aggarwal',
  'Hitesh Rathi','Hina Mirza','Hardik Patel','Harini Nair','Hema Reddy',
  'Heena Kulkarni','Hemendra Goel','Hiren Bansal','Hrishikesh Chauhan','Harpreet Singh',
  // I
  'Isha Kapoor','Ishan Bajaj','Indira Sharma','Ishita Gupta','Indrajit Pillai',
  'Iravati Rao','Irfan Khan','Imran Ansari','Iqbal Mirza','Indu Chauhan',
  // J
  'Jagdish Tiwari','Jatin Khurana','Jyoti Nambiar','Jaya Reddy','Jeetendra Kulkarni',
  'Jasleen Kaur','Jaspreet Singh','Jhanvi Sharma','Jigar Patel','Jignesh Mehta',
  'Jinal Nair','Jinesh Joshi','Jitendra Yadav','Joita Bansal','Juhi Chauhan',
  // K
  'Kabir Saxena','Kavya Menon','Krish Pandey','Kritika Jain','Kiran Rathi',
  'Komal Dixit','Kunal Arora','Karan Malhotra','Kartik Sethi','Kajal Sharma',
  'Kalyani Iyer','Kamini Pillai','Kanchan Rao','Kapil Tiwari','Karishma Gupta',
  'Kedar Kulkarni','Ketan Patel','Kinjal Mehta','Kirti Nair','Koel Reddy',
  'Kranti Bansal','Krati Chauhan','Krishna Naidu','Krunal Oberoi','Kumari Solanki',
  // L
  'Lakshmi Iyer','Lalit Chandra','Lata Hegde','Lavanya Rao','Leela Pillai',
  'Lisha Sharma','Lokesh Mehta','Lucky Singh','Lata Srivastava','Lavina Desai',
  // M
  'Manav Bose','Manisha Pillai','Mohit Choudhary','Manish Oberoi','Megha Solanki',
  'Madhuri Iyer','Mahesh Naidu','Mohana Reddy','Monika Trivedi','Mridul Bose',
  'Mukesh Dube','Mohd Irfan','Manas Tiwari','Manasi Joshi','Manoj Verma',
  'Manorama Saxena','Mayank Mishra','Meena Yadav','Meetali Gupta','Meghna Pillai',
  'Milan Patel','Milind Mehta','Minakshi Nair','Mira Reddy','Mitali Kulkarni',
  'Mitesh Goel','Mohan Bansal','Mohini Chauhan','Mona Singh','Mrinal Bhatt',
  // N
  'Neha Aggarwal','Nikhil Rao','Nisha Sinha','Namita Saxena','Nandini Menon',
  'Naveen Jain','Navya Pillai','Nidhi Bhatt','Nitin Lal','Nisha Wagle',
  'Naman Mirza','Nancy Patil','Nandkishore Ghosh','Naresh Dixit','Natasha Mathur',
  'Neeraj Agarwal','Neeta Bhat','Nikhita Rathi','Nilesh Kulkarni','Nilima Goel',
  'Nimisha Bansal','Nishant Chauhan','Nishka Tiwari','Nitisha Verma','Nitu Saxena',
  // O
  'Om Prakash','Omkar Rao','Omi Pillai','Omveer Singh','Ojasvi Sharma',
  // P
  'Pallavi Mishra','Parth Desai','Pooja Chauhan','Prachi Vyas','Pranav Khatri',
  'Priya Nambiar','Payal Patil','Pinki Ghosh','Piyush Thakur','Pratik Mathur',
  'Preethi Agarwal','Preeti Bhat','Prince Rathi','Puja Kulkarni','Purvi Goel',
  'Padma Iyer','Palak Mehta','Pankaj Sharma','Pari Gupta','Parinaz Khan',
  'Parineeta Rao','Parminder Kaur','Parvati Pillai','Pavan Reddy','Pavani Tiwari',
  'Pawan Mishra','Piyali Bose','Poorva Joshi','Pragati Verma','Prajakta Saxena',
  'Prakash Yadav','Pramod Pillai','Prasad Naidu','Prashant Oberoi','Pratima Solanki',
  'Praveen Ahmed','Prerna Trivedi','Priyanshi Bose','Priyanka Dube','Priyesh Saxena',
  // R
  'Rahul Bajaj','Rajan Trivedi','Rakesh Dube','Riddhi Kulkarni','Rishabh Goel',
  'Rohit Bansal','Ruchi Bhatt','Rashmi Gupta','Ravi Yadav','Reena Sinha',
  'Rekha Kapur','Renu Pandey','Ritesh Joshi','Ritu Arora','Rohini Verma',
  'Roshan Patel','Rupali Mehta','Radhika Nair','Raghav Tiwari','Rahila Khan',
  'Raj Malhotra','Rajat Sethi','Rajendra Rathi','Rajeshwari Dixit','Rajiv Chandra',
  'Raksha Hegde','Ramkumar Naidu','Ramona Oberoi','Ranjit Solanki','Ranjita Ahmed',
  'Rashi Trivedi','Ratan Bose','Raveena Dube','Raviraj Saxena','Reetika Menon',
  'Remya Jain','Renuka Pillai','Resham Bhatt','Richa Lal','Ridhi Wagle',
  'Rinki Mirza','Rinku Patil','Rita Ghosh','Ritika Thakur','Riya Mathur',
  'Romil Agarwal','Ronit Bhat','Roohi Rathi','Roopa Kulkarni','Roshan Goel',
  'Rucha Bansal','Rudra Chauhan','Ruhi Tiwari','Rupa Verma','Rutvik Saxena',
  // S
  'Sachin Lal','Sakshi Srivastava','Sameer Mathur','Sana Mirza','Sanjay Patil',
  'Shreya Ghosh','Shubham Dixit','Sneha Wagle','Sohail Sheikh','Swati Thakur',
  'Saloni Sharma','Sandeep Kumar','Sandhya Nair','Sanika Reddy','Sanjana Tiwari',
  'Santosh Malhotra','Sapna Sethi','Sarika Rathi','Satish Dixit','Seema Chandra',
  'Shashank Hegde','Shivam Naidu','Shivani Oberoi','Shruti Solanki','Siddharth Ahmed',
  'Simran Trivedi','Smita Bose','Sonam Dube','Sonali Saxena','Subhash Menon',
  'Sudhir Jain','Sujata Pillai','Sunil Bhatt','Sunita Lal','Suresh Wagle',
  'Sweta Mirza','Sabrina Patil','Sahil Ghosh','Samir Thakur','Sanjeev Mathur',
  'Sarita Agarwal','Saroj Bhat','Saurabh Rathi','Savita Kulkarni','Sayali Goel',
  'Sehal Bansal','Sejal Chauhan','Shailaja Tiwari','Shailesh Verma','Shalu Saxena',
  'Shama Menon','Shamim Jain','Shantanu Pillai','Sharda Bhatt','Sharmin Lal',
  'Sharon Wagle','Shefali Mirza','Shekhar Patil','Shirin Ghosh','Shital Thakur',
  'Shivendra Mathur','Shraddha Agarwal','Shravani Bhat','Siddhi Rathi','Smriti Kulkarni',
  'Snehal Goel','Soumya Bansal','Spandana Chauhan','Srikanth Tiwari','Sucharita Verma',
  'Sudha Saxena','Sumit Menon','Sunanda Jain','Supriya Pillai','Surbhi Bhatt',
  'Surendra Lal','Swapnil Wagle','Swara Mirza','Swarnalata Patil','Syeda Ghosh',
  // T
  'Tanvi Agarwal','Tarun Bhat','Tejal Ghosh','Trisha Thakur','Tushar Mathur',
  'Tanika Patil','Tanya Sharma','Tapas Mehta','Tarannum Khan','Tejas Nair',
  'Tejasvi Reddy','Tina Tiwari','Trupti Kulkarni','Tulsi Goel','Twinkle Bansal',
  // U
  'Uday Rathi','Uma Agarwal','Umesh Bhat','Utkarsh Rathi','Usha Singh',
  'Ujjwal Sharma','Upasana Mehta','Urmila Nair','Uttara Reddy','Urvashi Tiwari',
  // V
  'Varun Chandra','Vidya Hegde','Vikram Naidu','Vinay Oberoi','Vandana Kulkarni',
  'Veena Goel','Vikas Bansal','Vipin Chauhan','Vivek Khatri','Yamini Bhatt',
  'Vaishnavi Sharma','Varsha Mehta','Vasudha Nair','Veda Reddy','Vibha Tiwari',
  'Vidhya Mishra','Vidushi Kulkarni','Vijay Goel','Vijayalakshmi Bansal','Vijeta Chauhan',
  'Vikrant Singh','Vimal Bhatt','Vimala Lal','Vipul Wagle','Vismay Mirza',
  'Vishal Patil','Vishakha Ghosh','Vishnu Thakur','Vishwas Mathur','Vrinda Agarwal',
  // Y & Z
  'Yash Solanki','Yogesh Singh','Zara Ahmed','Zahir Khan','Zoya Mirza',
  'Yashaswini Sharma','Yatin Mehta','Yuvraj Nair','Zainab Ansari','Zeenat Siddiqui',
  // Extra (to reach 500)
  'Aarohi Verma','Abha Mishra','Achyut Nair','Adhira Patel','Advaita Joshi',
  'Agastya Mehta','Agrima Singh','Ahana Rao','Ahaana Pillai','Ahilya Reddy',
  'Akira Sharma','Akshat Gupta','Alisha Khan','Alvira Ansari','Ambar Tiwari',
  'Ambika Saxena','Amey Kulkarni','Amisha Goel','Amita Bansal','Amitabh Chauhan',
];

const _usedBuiltinNames = new Map(); // userId → Set of recently used indices

function pickBuiltinName(userId) {
  if (!_usedBuiltinNames.has(userId)) _usedBuiltinNames.set(userId, new Set());
  const used = _usedBuiltinNames.get(userId);
  if (used.size >= BUILTIN_NAMES.length) used.clear(); // reset when all used
  let idx;
  do { idx = Math.floor(Math.random() * BUILTIN_NAMES.length); } while (used.has(idx));
  used.add(idx);
  return BUILTIN_NAMES[idx];
}

export function getRandomBuiltinNames(count) {
  const shuffled = [...BUILTIN_NAMES].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, Math.min(count, BUILTIN_NAMES.length));
}

// ── Random shoutout timers ────────────────────────────────────────────────────
const randomShoutoutTimers = new Map(); // userId → intervalId

export function startRandomShoutout(userId, intervalMs, db, io) {
  stopRandomShoutout(userId);
  const id = setInterval(async () => {
    try {
      // Prefer name bank if uploaded, otherwise use built-in pool
      const { rows } = await db.query(
        'SELECT name FROM magic_live_name_bank WHERE user_id = ? ORDER BY RAND() LIMIT 1',
        [userId]
      ).catch(() => ({ rows: [] }));
      const name = rows.length ? rows[0].name : pickBuiltinName(userId);
      io.to(`magic:${userId}`).emit('show-shoutout', { name });
    } catch (_) {
      // Fallback to built-in names on any error
      io.to(`magic:${userId}`).emit('show-shoutout', { name: pickBuiltinName(userId) });
    }
  }, intervalMs);
  randomShoutoutTimers.set(userId, id);
}

export function stopRandomShoutout(userId) {
  const id = randomShoutoutTimers.get(userId);
  if (id) { clearInterval(id); randomShoutoutTimers.delete(userId); }
}

// ── Token refresh ─────────────────────────────────────────────────────────────
async function refreshToken(refreshTokenStr) {
  const res = await axios.post('https://oauth2.googleapis.com/token', {
    client_id:     process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    refresh_token: refreshTokenStr,
    grant_type:    'refresh_token',
  });
  return { accessToken: res.data.access_token, expiry: Date.now() + res.data.expires_in * 1000 };
}

// ── YouTube Live Chat polling ─────────────────────────────────────────────────
export async function startChatPoller(userId, accessToken, refreshTokenStr, tokenExpiry, db, io) {
  if (userPollers.has(userId)) return; // already running

  let token      = accessToken;
  let expiry     = tokenExpiry || 0;
  let liveChatId = null;
  let pageToken  = null;
  const processedIds = new Set();

  async function ensureToken() {
    if (Date.now() > expiry - 120_000) {
      const refreshed = await refreshToken(refreshTokenStr);
      token  = refreshed.accessToken;
      expiry = refreshed.expiry;
      // Persist updated token to DB
      await db.query(
        `UPDATE social_accounts SET access_token = ?, token_expiry = ? WHERE user_id = ? AND platform = 'youtube'`,
        [token, expiry, userId]
      ).catch(() => {});
    }
    return token;
  }

  async function fetchLiveChatId() {
    const t = await ensureToken();
    const res = await axios.get('https://www.googleapis.com/youtube/v3/liveBroadcasts', {
      params: { part: 'snippet', broadcastStatus: 'active', mine: true },
      headers: { Authorization: `Bearer ${t}` },
    });
    const items = res.data.items || [];
    if (!items.length) return null;
    return items[0].snippet.liveChatId || null;
  }

  async function pollMessages() {
    try {
      const t = await ensureToken();

      // Find active broadcast if we don't have liveChatId yet
      if (!liveChatId) {
        liveChatId = await fetchLiveChatId();
        if (!liveChatId) return; // no active stream yet — keep retrying
      }

      const params = { part: 'snippet,authorDetails', liveChatId, maxResults: 200 };
      if (pageToken) params.pageToken = pageToken;

      const res = await axios.get('https://www.googleapis.com/youtube/v3/liveChat/messages', {
        params,
        headers: { Authorization: `Bearer ${t}` },
      });

      pageToken = res.data.nextPageToken || null;
      const items = res.data.items || [];

      for (const item of items) {
        const msgId = item.id;
        if (processedIds.has(msgId)) continue;
        processedIds.add(msgId);

        // Keep processedIds from growing unbounded
        if (processedIds.size > 2000) {
          const first = processedIds.values().next().value;
          processedIds.delete(first);
        }

        const text       = item.snippet?.displayMessage || '';
        const authorName = item.authorDetails?.displayName || '';
        const authorId   = item.authorDetails?.channelId || authorName;

        // Poll vote detection (runs for every message regardless of "magic" keyword)
        const poll = getPoll(userId);
        if (poll && poll.active) {
          const letter = text.trim().toUpperCase();
          const vidx = ['A','B','C','D'].indexOf(letter);
          if (vidx >= 0 && vidx < poll.options.length) {
            const voted = castVote(userId, authorId, authorName, vidx);
            if (voted) {
              io.to(`magic:${userId}`).emit('poll-update', {
                votes: poll.votes,
                total: poll.voters.size,
              });
            }
            continue; // don't treat A/B/C/D as a "magic" trigger
          }
        }

        if (!/\bmagic\b/i.test(text)) continue;

        // Cooldown check
        if (!cooldowns.has(userId)) cooldowns.set(userId, new Map());
        const userCooldown = cooldowns.get(userId);
        const lastTime     = userCooldown.get(authorName) || 0;
        if (Date.now() - lastTime < COOLDOWN_MS) continue;
        userCooldown.set(authorName, Date.now());

        const result = addToQueue(userId, authorName, 'chat');
        if (result.ok) {
          // Log to history
          db.query(
            'INSERT INTO magic_live_history (user_id, name, source) VALUES (?, ?, ?)',
            [userId, result.name, 'chat']
          ).catch(() => {});

          // Notify dashboard
          io.to(`magic:${userId}`).emit('queue-update', getQueue(userId));
        }
      }
    } catch (err) {
      if (err.response?.status === 403 || err.response?.status === 404) {
        // Stream ended or chat removed — reset liveChatId to retry on next poll
        liveChatId = null;
        pageToken  = null;
      }
      // Other errors: silently continue
    }
  }

  const intervalId = setInterval(pollMessages, POLL_INTERVAL);
  userPollers.set(userId, { intervalId, processedIds, get token() { return token; } });

  // Mark active in DB
  await db.query(
    `INSERT INTO magic_live_settings (user_id, is_active) VALUES (?, 1)
     ON DUPLICATE KEY UPDATE is_active = 1`,
    [userId]
  ).catch(() => {});
}

export async function stopChatPoller(userId, db) {
  const poller = userPollers.get(userId);
  if (poller) {
    clearInterval(poller.intervalId);
    userPollers.delete(userId);
  }
  cooldowns.delete(userId);

  await db.query(
    `UPDATE magic_live_settings SET is_active = 0 WHERE user_id = ?`,
    [userId]
  ).catch(() => {});
}

// ── Settings helpers ──────────────────────────────────────────────────────────
export async function getSettings(userId, db) {
  try {
    const { rows } = await db.query(
      `SELECT anim_style, anim_speed, font_style, is_active, header_text,
              random_shoutout_enabled, random_shoutout_interval, correct_shoutout_count,
              session_active
       FROM magic_live_settings WHERE user_id = ? LIMIT 1`,
      [userId]
    );
    if (rows.length) return rows[0];
  } catch (_) {
    // Newer columns may not exist yet — fall back to minimal query
    const { rows } = await db.query(
      'SELECT anim_style, anim_speed, font_style, is_active FROM magic_live_settings WHERE user_id = ? LIMIT 1',
      [userId]
    );
    if (rows.length) return rows[0];
  }
  return { anim_style: 'neon', anim_speed: 'normal', font_style: 'bold', is_active: 0,
           random_shoutout_enabled: 0, random_shoutout_interval: 120, correct_shoutout_count: 5 };
}

export async function upsertSettings(userId, { animStyle, animSpeed, fontStyle, headerText }, db) {
  try {
    await db.query(
      `INSERT INTO magic_live_settings (user_id, anim_style, anim_speed, font_style, header_text)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE anim_style = VALUES(anim_style), anim_speed = VALUES(anim_speed),
         font_style = VALUES(font_style), header_text = VALUES(header_text)`,
      [userId, animStyle, animSpeed, fontStyle || 'bold', headerText || "Q&A — Only 20% Can Answer!"]
    );
  } catch (_) {
    // header_text column missing — update without it
    await db.query(
      `INSERT INTO magic_live_settings (user_id, anim_style, anim_speed, font_style)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE anim_style = VALUES(anim_style), anim_speed = VALUES(anim_speed), font_style = VALUES(font_style)`,
      [userId, animStyle, animSpeed, fontStyle || 'bold']
    );
  }
}
