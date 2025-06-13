package com.example.courseworkLuchnetskyi.service;

import com.example.courseworkLuchnetskyi.dto.request.PlayerRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.PlayerResponseDto;
import com.example.courseworkLuchnetskyi.dto.PlayerStatisticsDto;
import com.example.courseworkLuchnetskyi.dto.TeamAverageAgeDto;

import java.util.List;

public interface PlayerService {
    PlayerResponseDto createPlayer(PlayerRequestDto dto);
    List<PlayerResponseDto> getPlayersByTeam(Long teamId);
    PlayerResponseDto updatePlayer(Long playerId, PlayerRequestDto dto);
    void deletePlayer(Long playerId);
    TeamAverageAgeDto getAverageAgeForTeam(Long teamId);
    List<PlayerStatisticsDto> getPlayerStatisticsByTeam(Long teamId);
}
