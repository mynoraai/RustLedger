use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use eframe::{App, egui};
use rust_pure_demo::{Ledger, LedgerEntry};

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Rust Pure Ledger",
        options,
        Box::new(|_cc| Ok(Box::new(LedgerApp::default()))),
    )
}

struct LedgerApp {
    ledger_path: PathBuf,
    entries: Vec<LedgerEntry>,
    payload_input: String,
    secret_input: String,
    timestamp_input: String,
    status: Option<String>,
}

impl Default for LedgerApp {
    fn default() -> Self {
        let mut app = Self {
            ledger_path: PathBuf::from("ledger.jsonl"),
            entries: Vec::new(),
            payload_input: String::new(),
            secret_input: String::new(),
            timestamp_input: String::new(),
            status: None,
        };
        if let Err(err) = app.refresh_entries() {
            app.status = Some(format!("Failed to load ledger: {err}"));
        }
        app
    }
}

impl App for LedgerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Ledger Entries");
            ui.horizontal(|ui| {
                if ui.button("Refresh").clicked() {
                    if let Err(err) = self.refresh_entries() {
                        self.status = Some(format!("Refresh failed: {err}"));
                    } else {
                        self.status = Some("Ledger reloaded".into());
                    }
                }
                ui.separator();
                ui.label(format!("Stored entries: {}", self.entries.len()));
            });

            ui.separator();
            egui::ScrollArea::vertical()
                .max_height(240.0)
                .show(ui, |ui| {
                    if self.entries.is_empty() {
                        ui.label("Ledger is empty.");
                    }
                    for entry in &self.entries {
                        ui.group(|ui| {
                            ui.label(format!("Index: {}", entry.index));
                            ui.label(format!("Timestamp: {}", entry.timestamp));
                            ui.label(format!("Payload: {}", entry.payload));
                            ui.label(format!("Prev hash: {}", entry.prev_hash));
                            ui.label(format!("Hash: {}", entry.hash));
                            ui.label(format!("Public key: {}", entry.public_key));
                            ui.label(format!("Signature: {}", entry.signature));
                        });
                    }
                });

            ui.separator();
            ui.heading("Append Entry");
            ui.label("Payload");
            ui.text_edit_singleline(&mut self.payload_input);

            ui.label("Secret key (base64)");
            ui.text_edit_singleline(&mut self.secret_input);

            ui.label("Timestamp (seconds, optional)");
            ui.text_edit_singleline(&mut self.timestamp_input);

            if ui.button("Append").clicked() {
                match self.append_entry() {
                    Ok(index) => {
                        self.status = Some(format!("Appended entry {index}"));
                    }
                    Err(err) => {
                        self.status = Some(format!("Append failed: {err}"));
                    }
                }
            }

            if let Some(status) = &self.status {
                ui.separator();
                ui.label(status);
            }
        });
    }
}

impl LedgerApp {
    fn refresh_entries(&mut self) -> Result<(), String> {
        let ledger = Ledger::open(&self.ledger_path).map_err(|err| err.to_string())?;
        self.entries = ledger.entries().to_vec();
        Ok(())
    }

    fn append_entry(&mut self) -> Result<u64, String> {
        if self.payload_input.trim().is_empty() {
            return Err("Payload cannot be empty".into());
        }
        if self.secret_input.trim().is_empty() {
            return Err("Secret key is required".into());
        }

        let timestamp = if self.timestamp_input.trim().is_empty() {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| err.to_string())?
                .as_secs()
        } else {
            self.timestamp_input
                .trim()
                .parse::<u64>()
                .map_err(|err| format!("Invalid timestamp: {err}"))?
        };

        let mut ledger = Ledger::open(&self.ledger_path).map_err(|err| err.to_string())?;
        let request = ledger
            .prepare_append(self.payload_input.clone(), &self.secret_input, timestamp)
            .map_err(|err| err.to_string())?;
        let entry = ledger.append(request).map_err(|err| err.to_string())?;

        if let Some(pos) = self
            .entries
            .iter()
            .position(|existing| existing.index == entry.index)
        {
            self.entries[pos] = entry.clone();
        } else {
            self.entries.push(entry.clone());
        }

        self.payload_input.clear();
        self.timestamp_input.clear();
        Ok(entry.index)
    }
}
