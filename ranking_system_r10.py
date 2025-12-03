# ranking_system_r07.py
import time
import random

class RankingHandlers:
    def __init__(self, create_packet_func):
        self.create_packet = create_packet_func
        self.rankings = {}  # user -> rank data
    
    def handle_rank(self, data, session):
        """Handle RANK command - ranking and statistics"""
        data_str = data.decode('latin1') if data else ""
        print(f"RANK: Ranking request: {data_str}")
        
        # Parse configuration fields
        config = {}
        for line in data_str.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                config[key] = value
        
        # Generate mock ranking data
        username = session.clientNAME
        if username not in self.rankings:
            self.rankings[username] = {
                'rank': random.randint(500, 2000),
                'wins': random.randint(0, 50),
                'losses': random.randint(0, 30),
                'rating': random.randint(1000, 2500)
            }
        
        rank_data = self.rankings[username]
        
        response_lines = [
            f"USER={username}",
            f"RANK={rank_data['rank']}",
            f"WINS={rank_data['wins']}",
            f"LOSS={rank_data['losses']}",
            f"RATING={rank_data['rating']}",
            f"TRACK={config.get('SET_TRACK', 'DAYTONA')}",
            f"LAPS={config.get('SET_RACELEN', '10')}",
            "STATUS=1"
        ]
        
        return self.create_packet('rank', '', '\n'.join(response_lines) + '\n')