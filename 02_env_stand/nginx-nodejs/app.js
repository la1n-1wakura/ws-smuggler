const WebSocket = require('ws');

const wss = new WebSocket.Server({ port: 3000 });

console.log('WebSocket сервер Node.js запущен на порту 3000');

wss.on('connection', (ws) => {
    console.log('Клиент подключился');
    
    ws.on('message', (message) => {
        const text = message.toString();
        console.log(`Получено: ${text}`);
        ws.send(`Эхо: ${text}`);
    });
    
    ws.on('close', () => {
        console.log('Клиент отключился');
    });
});
