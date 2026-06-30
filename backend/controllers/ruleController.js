import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { rulesEngine } from '../engines/rulesEngine.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const customRulesPath = path.join(__dirname, '../rules/custom.json');

export function getRules(req, res) {
  try {
    let customRules = [];
    if (fs.existsSync(customRulesPath)) {
      customRules = JSON.parse(fs.readFileSync(customRulesPath, 'utf8'));
    }
    res.json({ systemRules: rulesEngine.rules, customRules });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

export function addRule(req, res) {
  try {
    const newRule = req.body;
    let customRules = [];
    
    if (fs.existsSync(customRulesPath)) {
      customRules = JSON.parse(fs.readFileSync(customRulesPath, 'utf8'));
    }

    newRule.id = `CUSTOM-${Date.now()}`;
    newRule.category = 'custom';
    customRules.push(newRule);

    fs.writeFileSync(customRulesPath, JSON.stringify(customRules, null, 2));
    
    // Reload into engine
    rulesEngine.rules.push(newRule);
    
    res.status(201).json(newRule);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

export function deleteRule(req, res) {
  try {
    const { id } = req.params;
    if (fs.existsSync(customRulesPath)) {
      let customRules = JSON.parse(fs.readFileSync(customRulesPath, 'utf8'));
      customRules = customRules.filter(r => r.id !== id);
      fs.writeFileSync(customRulesPath, JSON.stringify(customRules, null, 2));
      
      // Remove from active engine
      rulesEngine.rules = rulesEngine.rules.filter(r => r.id !== id);
    }
    res.status(200).json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}
